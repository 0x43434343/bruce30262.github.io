---
title: HITCON CTF 2016 Quals -- flame
tags:
  - ruby
  - CTF
  - HITCON
  - Reversing
  - PPC
  - PowerPC
  - assembly
  - qemu
  - C
categories:
  - write-ups
date: 2016-10-10 16:06:00
---
**Category:** PPC ( more like Reverse )
**Points:** 150

<!-- more -->  

We were given a 32 bit PowerPC ELF.  
Fortunately I've got **qemu-ppc-static** installed on my [ctf-box](https://github.com/bruce30262/ctf-box), so we can actually run the program by the following command:  
```
# root @ 9c51322c8256 in /mnt/files/hitcon-ctf-2016-qual/flame [7:51:02] 
$ qemu-ppc-static ./flame
*************************************
*                                   *
*   HITCON CTF 2016 Flag Verifier   *
*                                   *
*************************************
Check your flag before submission: AAAA
Your flag is incorrect :(
```

Kind of appreciate that this is a static linked binary, because if it's a dynamic linked binary then I'll have to spend more time to installed the PPC version of libc.  
  
Anyway we can see that the program will ask us to input the flag, and check if the flag is correct or not.

To do the dynamic analysis, I first use `qemu-ppc-static -g 10001 ./flame` to launch the program and listen for a gdb connection at port 10001, then I use **gdb-multiarch** to debug the program with `target remote localhost:10001`. As for the static analysis, I launch the program with IDA Pro.

After done some reversing, I summarize the program behavior with the following pseudo code:  
```c
int main()
{
    scanf("%s", flag); // let's just ignore the buffer overflow lol
    if( strlen(flag) == 35)
    {
        srandom(0x1e61);
        int i;
        for (i = 0 ; i < 35 ; i++)
        {
            r = rand();
            check[i] = flag[i] ^ (r & 0xfff);
        }
        for (i = 0 ; i < 35 ; i++)
        {
            if ( check[i] != secret[i] )
            {
                fail();
            }
        }
        success();
    }
    else
    {
        fail();
    }
}
```

The most challenging part is the line `check[i] = flag[i] ^ (r & 0xfff);`, it actually look like this in the PowerPC assembly: 

```
// r = rand();
bl        rand
mr        r9, r3
// r = r & 0xfff
clrlwi    r10, r9, 20 <-- clear the high-order 20 bits
lwz       r9, 0x18(r31)
slwi      r9, r9, 2
addi      r8, r31, 0x1A0
add       r9, r8, r9
addi      r9, r9, -0x180
stw       r10, 0(r9)
lwz       r9, 0x18(r31)
slwi      r9, r9, 2
addi      r10, r31, 0x1A0
add       r9, r10, r9
addi      r9, r9, -0x180
lwz       r9, 0(r9)
mr        r8, r9
// c = flag[i]
addi      r10, r31, 0x138
lwz       r9, 0x18(r31)
add       r9, r10, r9
lbz       r9, 0(r9)
// check[i] = c ^ r
xor       r9, r8, r9
mr        r10, r9
lwz       r9, 0x18(r31)
slwi      r9, r9, 2
addi      r8, r31, 0x1A0
add       r9, r8, r9
addi      r9, r9, -0x180
stw       r10, 0(r9)
// i++
lwz       r9, 0x18(r31)
addi      r9, r9, 1
stw       r9, 0x18(r31)
```

Took me a while to figure out the whole operation.  

So now we know that the flag is a string with 35 characters. The program will do some operation on our input, then store the result into the `check` buffer. Then it will compare each byte between the `check` buffer and the `secret` buffer, and print out the success message if their content were the same. 

We can dump the content of the `secret` buffer by using the debbuger. 

```
0xf6fff86c:     0x00000cfe      0x00000859      0x0000095d      0x00000871
0xf6fff87c:     0x0000040d      0x00000006      0x00000ade      0x00000fa8
0xf6fff88c:     0x00000561      0x000009da      0x00000878      0x00000682
0xf6fff89c:     0x00000fa9      0x00000f5f      0x0000025e      0x00000db0
0xf6fff8ac:     0x00000fbf      0x00000bc6      0x00000d38      0x0000095d
0xf6fff8bc:     0x00000d09      0x000007ed      0x00000307      0x000001c0
0xf6fff8cc:     0x00000399      0x00000956      0x00000a45      0x00000292
0xf6fff8dc:     0x00000c8a      0x0000092f      0x0000004a      0x00000964
0xf6fff8ec:     0x00000194      0x000009da      0x0000011f      
```


After that, we can just recover the flag by writing some simple scripts.  
```ruby sol.rb
#!/usr/bin/env ruby

resp = `./test`.split("\n")
seed = []
ans =[0x00000cfe, 0x00000859, 0x0000095d, 0x00000871, 0x0000040d,0x00000006,0x00000ade, 0x00000fa8, 0x00000561,  0x000009da , 0x00000878, 0x00000682, 0x00000fa9 , 0x00000f5f, 0x0000025e, 0x00000db0, 0x00000fbf, 0x00000bc6 , 0x00000d38 , 0x0000095d, 0x00000d09, 0x000007ed , 0x00000307, 0x000001c0, 0x00000399, 0x00000956 , 0x00000a45 , 0x00000292, 0x00000c8a,0x0000092f , 0x0000004a , 0x00000964, 0x00000194,  0x000009da, 0x0000011f]
 
for s in resp
    seed << (s.to_i(16) & 0xfff)
end

flag = ""

for a,b in seed.zip(ans)
    flag += (a^b).chr
end

puts flag

```

`test` is a C program for generating the random seed  
```c test.c
#include <stdio.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    int i = 0;
    srand(0x1e61);
    for(i = 0 ; i < 35 ; i++)
    {
        printf("0x%x\n", rand());
    }
    return 0;
}
```

Result:  
```
# root @ 9c51322c8256 in /mnt/files/hitcon-ctf-2016-qual/flame [8:42:43] C:126
$ ruby ./sol.rb 
hitcon{P0W3rPc_a223M8Ly_12_s0_345y}
```
  
flag: `hitcon{P0W3rPc_a223M8Ly_12_s0_345y}`

  
  

References of PowerPC:
* [PowerPC Assembly tutorial](http://www.csd.uwo.ca/~mburrel/stuff/ppc-asm.html)
* [Assembler Tutorial - WiiBrew](http://wiibrew.org/wiki/Assembler_Tutorial)