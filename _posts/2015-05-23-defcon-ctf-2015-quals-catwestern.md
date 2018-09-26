---
title: DEFCON CTF 2015 Quals -- catwestern
tags:
  - Python
  - CTF
  - DEFCON
  - PPC
  - C
  - assembly
categories:
  - write-ups
date: 2015-05-23 22:39:00
---
**Category:** Coding Challenge
**Points:** 1
> meow
> catwestern_631d7907670909fc4df2defc13f2057c.quals.shallweplayaga.me 9999

<!-- more -->

Interesting challenge. First we connect to the service, it will send us the following message:

```
****Initial Register State****
rax=0xfcf7659c7a4ad096
rbx=0x1df0e8dfe8f70b53
rcx=0x55004165472b9655
rdx=0x1aa98e77006adf1
rsi=0x949a482579724b11
rdi=0x1e671d7b7ef9430
r8=0x3251192496cee6a6
r9=0x278d01e964b0efc8
r10=0x1c5c8cca5112ad12
r11=0x75a01cef4514d4f5
r12=0xe109fd4392125cc7
r13=0xe5e33405335ba0ff
r14=0x633e16d0ec94137
r15=0xb80a585e0cd42415
****Send Solution In The Same Format****
About to send 74 bytes: 
hŒråRI‡Ô�A]HÿÊI�Ç¢éNhIÿÊHÿÃ�HÎI�Ç^�…6H¤Ã
                                       M�ÃI÷ëH)ðH�ÆQØ8e�HÿÀIÁÕ�H5Œm'�Ã^C
```

So it seem like the service gave us the registers' inital value, and a sequence of machine code. Apparently, they want us to execute the machine code and send them all the register values after the execution.  

After some thinking and researching, I decide to solve the challenge by using the following method:  

First, get all the registers' initial value and construct the machine code, start with `mov [reg], [val]`. Then, receive the machine code from the server, and append it to the current machine code. So the final machine code will be like this: 

```
; if we convert it to assembly
mov rax, XXX
mov rbx, XXX
mov rcx, XXX
............
mov r15, XXX
[server's machine code]
```

Now all we have to do is to execute the machine code and get all the registers' value. To achieve this requirement, I prepared a C code:

```c shell.c
char code[] = machine ;

int main(int argc, char **argv)
{
    int (*func)();
    func = (int (*)()) code;
    (int)(*func)(); // execute the machine code
    int a = 0; // line 8, our break point to check the register values
    return 0;
}
```

**"machine"** will be replace by the machine code I have (by using the `sed` command). After we finish building the C file, we can compile it by using the `gcc -g -z execstack -o real real.c` command.  

Now we'll just need to excute the binary file we have compiled. I decide to execute it with gdb, since it'll make me more easier to get the register values. So now the problem is **how do we get the output from gdb by using python?** Fortunately, with the help of the internet, I found [this link](http://parsiya.net/blog/2014-05-25-pasting-shellcode-into-gdb-using-python/), which is pretty useful for me to solve the challenge. All I need to do is call gdb by using Popen, send 3 command to it (`b 8`, `r` & `i r`), then parse the result and send the answer to the server.

Here's the final script:
```python code.py
from pwn import *
from subprocess import Popen , PIPE
from time import sleep
import sys
import os

HOST = "catwestern_631d7907670909fc4df2defc13f2057c.quals.shallweplayaga.me"
PORT = 9999

context.arch = "x86_64"
context.os = 'linux'
context.endian = 'big'

r = remote(HOST, PORT)

def getoutput(proc):
    print "the output"
    s = ""
    while True:
        out = proc.stdout.read(1)
        if out == '' and proc.poll() != None:
            break
        else:
            s += out
            # recv until the end of the color code(generate by gdb-peda)
            if '20011b5b306d02'.decode('hex') in s:
                return s

def get_ans():
    proc = Popen( ['gdb' , './real'] , bufsize=1 ,stdin=PIPE, stdout=PIPE )
    s = getoutput(proc)

    print "sending b 8" # break at line 8
    proc.stdin.write('b 8\n')
    sleep(0.5)
    s = getoutput(proc)

    print "sending r" # start running
    proc.stdin.write('r\n')
    sleep(0.5)
    s = getoutput(proc)

    print "sending i r" # get the register values
    proc.stdin.write('i r\n')
    sleep(0.5)
    s = getoutput(proc)
    proc.stdin.close()
    
    # parse the result
    ans = ""
    all_register = s.split('\n')
    for c in all_register:
        temp = c.split(' ')
        if temp[0] in register:
            ans += temp[0].strip() + "=" + temp[len(temp)-1].split('\t')[0].strip()
            ans += '\n'

    log.success("ans:")
    print ans
    r.send(ans)
    print r.recv(1024)

# recv registers' state
r.recvuntil("****Initial Register State****")
s = r.recvuntil("****Send Solution In The Same Format****")
print s
temp = s.split("\n")
register = dict()

# setting registers' dict
for index, c in enumerate(temp):
    if "=" in c:
        name = c.split("=")[0]
        val = c.split("=")[1]
        register[name] = int(val, 16)

# adding mov [reg], [val]
machine_code = ""
for key, val in register.items():
    s = "mov "+str(key)+", "+hex(val)
    machine_code += asm(s).encode('hex')

# receiving machine code
print r.recvuntil("bytes: \n")
s = r.recv(1024)

# appending machine code
machine_code += s.encode('hex')
machine = "\""
for c in machine_code.decode('hex'):
    machine += "\\\\x"+c.encode('hex')
machine += "\""

# contructing real.c
cmd = "sed \'s|machine|"+machine+"|g' < shell.c > real.c"
os.system(cmd)
print disasm(machine_code.decode('hex'))
os.system('gcc -g -z execstack -o real real.c')
get_ans()

r.interactive()

```

Notice the line `context.endian = 'big'`. At first I use the **little endian** to solve the challenge, which gave me "Invalid solution" everytime I send the answer. Just before I was about to give up, teammate **bletchley** suggest me to change the endianness into big endian. And guess what? The flag appears on the screen right after I change the word "little" into "big"! What an end!

Flag: `Cats with frickin lazer beamz on top of their heads!`