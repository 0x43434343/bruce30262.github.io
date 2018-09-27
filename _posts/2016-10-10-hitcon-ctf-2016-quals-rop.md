---
title: HITCON CTF 2016 Quals -- ROP
layout: single
comments: true
share: true
related: true
author_profile: true
permalink: "/:title/"
tags:
- CTF
- HITCON
- ruby
- Reversing
categories:
- write-ups
date: '2016-10-10 16:07:00 +0000'
---

**Category:** Reverse
**Points:** 250

<!-- more -->  

The challenge gave us a file call `rop.iseq`. By checking the file header, I found that it was a binary format of Ruby's [InstructionSequence](https://ilconnettivo.wordpress.com/2015/12/25/ruby-2-3-0-instructionsequence/). 

By googling the InstructionSequence, I found that there are some new features were added into the ruby version 2.3, for example the [load_from_binary](http://ruby-doc.org/core-2.3.0/RubyVM/InstructionSequence.html#method-c-load_from_binary) method. We can actually use these methods to load the instruction sequence from a binary file, and disassemble the instruction to a human readable format.  

```ruby
#!/usr/bin/env ruby

# read rop.iseq, dump InstructionSequence

f = open("rop.iseq", "rb")
a = f.read()
d = RubyVM::InstructionSequence.load_from_binary(a)

#d.eval #execute the instruction sequence
puts d.disasm # print out the disassemble result
```

If we execute the line `d.eval`, it will run the instruction sequence:
```
bruce30262@ubuntu:~/Desktop$ ruby ./de.rb 
AAAA
Invalid Key @_@
```

Looks like the program will read our input and do some checking, then output the checking result.   

Anyway let's dump the disassemble result and start reversing. [Here](https://gist.github.com/bruce30262/1e8fd1439f13e75cf72e0c265dd612de)'s the whole disassemble result.  
```
== disasm: #<ISeq:<compiled>@<compiled>>================================
== catch table
| catch type: break  st: 0096 ed: 0102 sp: 0000 cont: 0102
| catch type: break  st: 0239 ed: 0245 sp: 0000 cont: 0245
|------------------------------------------------------------------------
local table (size: 3, argc: 0 [opts: 0, rest: -1, post: 0, block: -1, kw: -1@-1, kwrest: -1])
[ 3] k          [ 2] xs         
0000 trace            1                                               (   1)
0002 putself          
0003 putstring        "digest"
0005 opt_send_without_block <callinfo!mid:require, argc:1, FCALL|ARGS_SIMPLE>, <callcache>
0008 pop              
0009 trace            1                                               (   2)
0011 putself          
0012 putstring        "prime"
0014 opt_send_without_block <callinfo!mid:require, argc:1, FCALL|ARGS_SIMPLE>, <callcache>
0017 pop              
0018 trace            1                                               (   4)
0020 putspecialobject 3
0022 putnil        
................................................
............... lots of stuff....................
0056 opt_send_without_block <callinfo!mid:gets, argc:0, ARGS_SIMPLE>, <callcache>
0059 opt_send_without_block <callinfo!mid:chomp, argc:0, ARGS_SIMPLE>, <callcache>
0062 setlocal_OP__WC__0 3
0064 trace            1                                               (  39)
0066 getlocal_OP__WC__0 3
0068 putstring        "-"
0070 opt_send_without_block <callinfo!mid:split, argc:1, ARGS_SIMPLE>, <callcache>
0073 setlocal_OP__WC__0 2
0075 trace            1                                               (  40)
0077 getlocal_OP__WC__0 2
0079 opt_size         <callinfo!mid:size, argc:0, ARGS_SIMPLE>, <callcache>
0082 putobject        5
0084 opt_eq           <callinfo!mid:==, argc:1, ARGS_SIMPLE>, <callcache>
0087 branchif         94
................................................
............... lots of stuff....................
```

Google is our friend. I found a useful [reference](http://kgrz.io/2014/04/19/ruby-trace-leave-oh-my.html) for introducing basic ruby instruction sequence reversing. 

For example for the following iseq:
```
0000 trace            1                                               (   1)
0002 putself          
0003 putstring        "digest"
0005 opt_send_without_block <callinfo!mid:require, argc:1, FCALL|ARGS_SIMPLE>, <callcache>
```

`trace 1` means "A new line of Ruby code has been encountered". Then by reading the following lines, we know that the line of the code was probably `require "digest"`.   

And so we can try to reverse the whole iseq by following the similar pattern. First we found the code that read the user input:
```
# input = gets.chomp
0056 opt_send_without_block <callinfo!mid:gets, argc:0, ARGS_SIMPLE>, <callcache>
0059 opt_send_without_block <callinfo!mid:chomp, argc:0, ARGS_SIMPLE>, <callcache>
0062 setlocal_OP__WC__0 3
```
So `local_OP__WC__0 3` will be our input. Now for the first check: 

```
# input.split("-")
0064 trace            1                                               (  39)
0066 getlocal_OP__WC__0 3
0068 putstring        "-"
0070 opt_send_without_block <callinfo!mid:split, argc:1, ARGS_SIMPLE>, <callcache>

# input.split("-").size == 5
0073 setlocal_OP__WC__0 2
0075 trace            1                                               (  40)
0077 getlocal_OP__WC__0 2
0079 opt_size         <callinfo!mid:size, argc:0, ARGS_SIMPLE>, <callcache>
0082 putobject        5
0084 opt_eq           <callinfo!mid:==, argc:1, ARGS_SIMPLE>, <callcache>
0087 branchif         94

# if input.split("-").size != 5, call gg() (which print "Invalid key @_@")
0089 putself          
0090 opt_send_without_block <callinfo!mid:gg, argc:0, FCALL|VCALL|ARGS_SIMPLE>, <callcache>
0093 pop             

# input.split("-").all? must be true
0094 trace            1                                               (  41)
0096 getlocal_OP__WC__0 2
0098 send             <callinfo!mid:all?, argc:0>, <callcache>, block in <compiled>
0102 branchif         109
0104 putself          
0105 opt_send_without_block <callinfo!mid:gg, argc:0, FCALL|VCALL|ARGS_SIMPLE>, <callcache>
```
We can see that the valid key format must be something like "X-X-X-X-X". Here I also found a sequence of iseq which help us infer the precise key format:

```
0000 trace            256                                             (  41)
0002 trace            1
0004 getlocal_OP__WC__0 2
0006 putobject        /^[0-9A-F]{4}$/ <-- here
0008 opt_regexpmatch2 <callinfo!mid:=~, argc:1, ARGS_SIMPLE>, <callcache>
0011 trace            512
```
So now we know that the key format is "XXXX-XXXX-XXXX-XXXX-XXXX", while "X" is in the range of `[0-9A-F]`. Time to recover the valid key.

The checking of the first part of the key was pretty simple: 
```
# local_OP__WC__0 2 = input.split("-"), let's call it key
0111 getlocal_OP__WC__0 2
0113 putobject_OP_INT2FIX_O_0_C_ 

# key[0].to_i(16) = 31337
0114 opt_aref         <callinfo!mid:[], argc:1, ARGS_SIMPLE>, <callcache>
0117 putobject        16
0119 opt_send_without_block <callinfo!mid:to_i, argc:1, ARGS_SIMPLE>, <callcache>
0122 putobject        31337
0124 opt_eq           <callinfo!mid:==, argc:1, ARGS_SIMPLE>, <callcache>
0127 branchif         134
```
So `key[0]` is `hex(31337)` = `7A69`
The checking of the second part of the key is even more simple:
```
# key[1].reverse == "FACE"
0136 getlocal_OP__WC__0 2
0138 putobject_OP_INT2FIX_O_1_C_ 
0139 opt_aref         <callinfo!mid:[], argc:1, ARGS_SIMPLE>, <callcache>
0142 opt_send_without_block <callinfo!mid:reverse, argc:0, ARGS_SIMPLE>, <callcache>
0145 putstring        "FACE"
0147 opt_eq           <callinfo!mid:==, argc:1, ARGS_SIMPLE>, <callcache>
0150 branchif         157
```
So `key[1]` = `"FACE".reverse` = `ECAF`. 

To verify if `key[0]` and `key[1]` were the right value, we can actually use the following command to trace the ruby code: `ruby -r tracer de.rb`. If the key was correct, it would perform more checking, which means it will execute more line of code, so we can know if a part of the key was right or wrong by observing the trace of the ruby tracer ( kind of a side-channel analysis. )

Back to our recovering procedure. The checking of the `key[2]` looks like this:
```
# call f(217, key[2].to_i(16), 314159)
0160 putobject        217
0162 getlocal_OP__WC__0 2
0164 putobject        2
0166 opt_aref         <callinfo!mid:[], argc:1, ARGS_SIMPLE>, <callcache>
0169 putobject        16
0171 opt_send_without_block <callinfo!mid:to_i, argc:1, ARGS_SIMPLE>, <callcache>
0174 putobject        314159
0176 opt_send_without_block <callinfo!mid:f, argc:3, FCALL|ARGS_SIMPLE>, <callcache>

# return_value.to_s(28).upcase should be "48D5"
0179 putobject        28
0181 opt_send_without_block <callinfo!mid:to_s, argc:1, ARGS_SIMPLE>, <callcache>
0184 opt_send_without_block <callinfo!mid:upcase, argc:0, ARGS_SIMPLE>, <callcache>
0187 putstring        "48D5"
0189 opt_eq           <callinfo!mid:==, argc:1, ARGS_SIMPLE>, <callcache>
0192 branchif         199
```
It will first call a method `f`, with argument (`217`, `key[2].to_i(16)`, `314159`), then check if its return value = `94449` ( with 28 as base, `48D5` is actually `94449` in base 10 )

method `f` was kind of complicated, so I will just post the pseudo code instead:
```ruby
def f(two17, key2, pi)
    ret = 1
    v2 = two17
    while key2 != 0
        if key2[0] == 1 # the first bit of current key2
            ret = (ret*v2)%pi
        end
        key2 = key2>>1
        v2 = (v2*v2)%pi
    end
    return ret
end
```

Since we know that `key[2]`'s format is `0000` ~ `FFFF`, we can just crack `key[2]` by writing a simple crackme:
```ruby
def f(two17, key2, pi)
    ret = 1
    v2 = two17
    while key2 != 0
        if key2[0] == 1 # the first bit of current key2
            ret = (ret*v2)%pi
        end
        key2 = key2>>1
        v2 = (v2*v2)%pi
    end
    return ret
end

for i in (0..0xffff)
    ret = f(217,i, 314159)
    if ret == 94449
        puts "got it!"
        puts i.to_s(16)
    end
end
```
And so we got the value of `key[2]`: `1BD2`

Moving on to the next part (`key[3]`):
```
0201 getlocal_OP__WC__0 2
0203 putobject        3
0205 opt_aref         <callinfo!mid:[], argc:1, ARGS_SIMPLE>, <callcache>
0208 putobject        10
0210 opt_send_without_block <callinfo!mid:to_i, argc:1, ARGS_SIMPLE>, <callcache>
0213 opt_send_without_block <callinfo!mid:prime_division, argc:0, ARGS_SIMPLE>, <callcache>
0216 putobject        :first
0218 send             <callinfo!mid:map, argc:0, ARGS_BLOCKARG>, <callcache>, nil
0222 opt_send_without_block <callinfo!mid:sort, argc:0, ARGS_SIMPLE>, <callcache>
0225 duparray         [53, 97]
0227 opt_eq           <callinfo!mid:==, argc:1, ARGS_SIMPLE>, <callcache>
0230 branchif         237
```

At first I was confused at line 0216 ~ 0218. There's a `:first` for `map`, but the argc of `map` was actually `0`. After doing some search on the internet, I found [this](http://qiita.com/yui-knk/items/f7ce1c3138ef44872d3b) post and found out that the check was actually doing:
```ruby
b = key[3].to_i(10).prime_division.map &:first
b.sort == [53,97]
```
So the value of `key[3]` is `53*97 == 5141` ( base 10 )

At this point we know the valid key is `7A69-ECAF-1BD2-5141-XXXX`. The checking of the last part of the key was also kind of complicated and I was kind of lazy to reverse the whole thing. So far we have the first four part of the key, and there's only one left ...... so why don't we use the old typical brute force attack to recover the last one ? ;)
```ruby
#!/usr/bin/env ruby
for i in (0..0xffff)
    key = "7A69-ECAF-1BD2-5141-%04X" % i
    cmd = "echo \"#{key}\"|ruby de.rb "
    puts cmd
    resp = `#{cmd}`
    if not resp.include?"Invalid"
        puts resp
        break
    end
end
```
And after about 20 minutes....
```
........................
echo "7A69-ECAF-1BD2-5141-CA70"|ruby de.rb
echo "7A69-ECAF-1BD2-5141-CA71"|ruby de.rb
echo "7A69-ECAF-1BD2-5141-CA72"|ruby de.rb
Congratz! flag is hitcon{ROP = Ruby Obsecured Programming ^_<}
```

Looks like I should brute force the key from `0xffff` down to `0` though :P
Anyway, the valid key is `7A69-ECAF-1BD2-5141-CA72`, and so we got the flag ! 

flag: `hitcon{ROP = Ruby Obsecured Programming ^_<}`