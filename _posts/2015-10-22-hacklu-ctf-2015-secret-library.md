---
title: Hack.lu CTF 2015 -- secret library
tags:
  - Hack.lu
  - Reversing
  - CTF
  - Python
categories:
  - write-ups
date: 2015-10-22 11:48:00
---
**Category:** Reversing
**Points:** 200  

[64 bit ELF](https://school.fluxfingers.net/static/chals/secret_library_75904fb763267c629e729fa4a5c4d967)

<!-- more -->  

This service is a some kind of weird library system, which has the following functions:
* View the book title. You'll have to be the **"head librarian" ( = admin)** first.
* View the book content (**If you know the exact book title**).
* Convert a binary string into a hex string (which is useless in this challenge).
* Let user to prove that he is the admin (will explain later).

According to the description, our goal is to read the book's content. To achieve this, we'll have to know the book title first, which can only be viewed by the **"head librarian" ( = admin)**. So the main challenge is to prove that we're the head librarian.  

To prove that we're the admin, we'll have to guess the correct value of a 4 byte data ( which is read from `/dev/urandom`) for **10 times continuously**. This seems impossible, since we have no output information of the random value. I was kind of stuck at that point for quite a while, until I found something weird in the function which check the user input:

```c
signed __int64 __fastcall check_invalid_char(char a1)
{
    signed __int64 result; // rax@2

    if ( a1 > '/' )
    {
        if ( a1 > '9' )
        {
            if ( a1 > '@' )
            {
                if ( a1 > 'F' )
                    result = 0xFFFFFFFFLL;
                else
                    result = (unsigned int)(a1 - 55);
            }
            else
            {
                __asm { syscall } // <-- WTF?
                result = 0xFFFFFFFFLL;
            }
        }
        else
        {
            result = (unsigned int)(a1 - '0');
        }
    }
    else
    {
        result = 0xFFFFFFFFLL;
    }
    return result;
}
```
The input checking function will check every character to make sure that it is a valid hex char. Once it found out that the character was invalid, it will `return -1`. What really caught my eye was the pseudo code `__asm { syscall }`. Why did it use the `syscall` instruction? Let's check the assembly:  

```
.text:0000000000400B21  mov     rax, 0Eh
.text:0000000000400B28  mov     rdi, 0
.text:0000000000400B2F  mov     rsi, 0
.text:0000000000400B36  mov     rdx, 603397h
.text:0000000000400B3D  mov     r10, 8
.text:0000000000400B44  syscall
```

So...it just call the system call `sigprocmask(0, NULL, 0x603397)`. After checking the [man page](http://linux.die.net/man/2/sigprocmask), I still don't know what `sigprocmask` does, but I found out that it clears the byte at `0x603397`. This discovery is important, because in order to be the head librarian, we'll have to let the data at `0x603394` be set to `0x00278F03`. If we can find a way that set the value at `0x603394` to `0xXX278F03` and trigger the `sigprocmask` syscall, then `0xXX278F03` will become `0x00278F03`, which will give us the admin privileges!  

After doing some analysis, I finally figured out how to beat the challenge:  
1. First, send the input `420B65F7`
2. The program will then ask us to input the "library card". We send `99278F03` instead of `00278F03`, because if we send `00278F03`, program will ask us to guess the random number, and it'll set the value at `0x603394` to `0` after we failed to guess the correct value. 
3. By sending `99278F03`, value at `0x603394` will become `99278F03`. It will failed the check though, but since the program did not ask us to guess the random number, it won't clear the data at `0x603394`, and so the value at `0x603394` will remain unchange.
4. Now we send an invalid input in order to trigger the `sigprocmask` syscall. The program will clear a byte at `0x603397`, changing `99278F03` into `00278F03`.
5. Now we can claim that we're the head librarian and check the book title + read the book content.
 
Here the script that I wrote to pass the challenge:
```python
#!/usr/bin/env python

from pwn import *

HOST = "school.fluxfingers.net"
PORT = 1527

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

if __name__ == "__main__":

    r = remote(HOST, PORT)

    r.sendlineafter("words.\n", "420B65F7")
    r.sendlineafter("card.\n", "99278F03")
    r.sendlineafter("alright!\n", ":\n123456") # trigger the sigprocmask syscall
    r.sendlineafter("right?\n", "952A7224")
    r.sendlineafter("16F7F4D391F030CF\n------------\n", "F1140B88")
    r.recvuntil("book.\n")
    r.sendline("16F7F4D3")
    r.sendline("91F030CF")

    r.interactive()

```
```
bruce30262@ubuntu:~/Desktop/hack.lu_2015/secret$ ./exp_secret.py 
[+] Opening connection to school.fluxfingers.net on port 1527: Done
[*] Switching to interactive mode
oh, yes, we have that! here you go...
flag{our_secret_is_that_we_really_just_have_this_one_book}

====================
$ 

```

Flag: `flag{our_secret_is_that_we_really_just_have_this_one_book}`
