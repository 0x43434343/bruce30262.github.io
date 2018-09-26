---
title: CSAW CTF 2015 -- wyvern
tags:
  - ruby
  - CTF
  - CSAW
  - Reversing
  - pin
  - side-channel-attack
categories:
  - write-ups
date: 2015-09-22 04:24:00
---
**Category:** Reversing
**Points:** 500 

Here they gave us another [64 bit ELF](https://github.com/ctfs/write-ups-2015/blob/master/csaw-ctf-2015/reverse/wyvern-500/wyvern_c85f1be480808a9da350faaa6104a19b), which is apparently written in **C++**.  

<!-- more -->

It will ask us to input a secret, and tell us if we failed or success. The checking secret part in the program was really hard to understand what the actual f\*ck is it doing, so I decide to reverse only the critical part.

```c++
 v7 = std::string::length(v12) - 1LL != legend >> 2;
 ..............
 if ( v7 )
 	/*do something*/
 else
 	/*do something*/
```

This is the partial pseudo code from the checking secret function. The variable `legend` was stored in the data segment `0x610138` with the initial value `0x73`. Knowing that `0x73 >> 2 == 28`, I'm guessing that the secret's length is going to be 28.  

To verify the assumption, I launch the program with gdb, and set the breakpoint at the end of the checking secret function. Then, I start sending the input with different length. I found out that when the input length is 28, the return value will be `0`, which is different from other inputs (return value = `0x1c`). Although I don't know the exact secret ( because the return value should be `1` for the correct secret ), I'm now quite sure that the secret length should be 28.  

Now let's take a look at other part of the checking function:  
```c++
if ( v7 )
{
    if ( y26 >= 10 && (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) != 0 )
        goto LABEL_14;
    while ( 1 )
    {
        *v9 = legend >> 2;
        if ( y26 < 10 || (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) == 0 )
            break;
LABEL_14:
        *v9 = legend >> 2;
    }
}
else
{
    if ( y26 >= 10 && (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) != 0 )
        goto LABEL_15;
    while ( 1 )
    {
        v1 = v12;
        std::string::string(v8, v12);
        if ( y26 < 10 || (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) == 0 )
            break;
LABEL_15:
        std::string::string(v8, v12);
    }
    v6 = sanitize_input(v8, v1);
    if ( y26 >= 10 && (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) != 0 )
        goto LABEL_16;
    while ( 1 )
    {
        *v9 = v6;
        std::string::~string(v8);
        if ( y26 < 10 || (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) == 0 )
            break;
LABEL_16:
        *v9 = v6;
        std::string::~string(v8);
    }
}
do
    v5 = *v9;
while ( y26 >= 10 && (((_BYTE)x25 - 1) * (_BYTE)x25 & 1) != 0 );
```

It will be a pain in the ass if we try to reverse the whole checking algorithm, so we're going to find some critical point. Notice that there're some while loop and some if-else condition in the checking function, so I assume that maybe ( just maybe ) the checking function will process the input characters one by one. If the current character failed to pass some specific condition, it will break out the loop immediately, failing the check. If it pass the specific condition successfully, it will continue the loop and check the next byte, which means that **it will run more instructions than the failing one**.  

It's like **side-channel attack**. We guess the current character, and count the instructions it ran. If we get a number that is larger than the others, we'll know that this might be the right character, and so we can move on to guessing the next character.  

To achieve this, I use [Intel pin](https://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool) to count the instructions number. Here's the script (written in ruby):

```ruby
#!/usr/bin/env ruby

all_str = []
for i in (48..57)
    all_str << i.chr
end
for i in (97..122)
    all_str << i.chr
end
for i in (65..90)
    all_str << i.chr
end
all_str << "_"
all_str << "@"
cur_max = 0
index = 0
key = ""

while true
    now = key + all_str[index]
    input = now.ljust(28, "1")
    puts "Trying: #{input}"
    cmd = "echo \"#{input}\" | /home/bruce30262/pin/pin -t /home/bruce30262/pin/source/tools/ManualExamples/obj-intel64/inscount0.so -- /home/bruce30262/CSAWCTF-2015/wyvern/wyvern; cat inscount.out"
    #puts cmd
    resp = `#{cmd}`
    cnt = resp.split("\n")[9].split(" ")[1].to_i
    puts cnt
    if cnt == 0
        puts "end"
        break
    end
    if cur_max == 0 or index == 0
        cur_max = cnt
        index += 1
    else
        if cnt > cur_max
            key = now
            puts "Key: #{key}"
            cur_max = cnt
            index = 0
        elsif cnt == cur_max
            index += 1
        end
    end
end

```

Run the script and wait a couple of minutes, we'll get the correct secret: 
```
.................
Trying: dr4g0n_or_p4tric1an_it5_LLVG
1700759
Trying: dr4g0n_or_p4tric1an_it5_LLVH
1700759
Trying: dr4g0n_or_p4tric1an_it5_LLVI
1700759
Trying: dr4g0n_or_p4tric1an_it5_LLVJ
1700759
Trying: dr4g0n_or_p4tric1an_it5_LLVK
1700759
Trying: dr4g0n_or_p4tric1an_it5_LLVL
1700759
Trying: dr4g0n_or_p4tric1an_it5_LLVM
0
end
```

Verify the secret:
```
bruce30262@ubuntu:~/CSAWCTF-2015/wyvern$ ./wyvern
+-----------------------+
|    Welcome Hero       |
+-----------------------+

[!] Quest: there is a dragon prowling the domain.
        brute strength and magic is our only hope. Test your skill.

Enter the dragon's secret: dr4g0n_or_p4tric1an_it5_LLVM
success

[+] A great success! Here is a flag{dr4g0n_or_p4tric1an_it5_LLVM}
```  
Cool! The flag is: `dr4g0n_or_p4tric1an_it5_LLVM` (without `flag{}`)