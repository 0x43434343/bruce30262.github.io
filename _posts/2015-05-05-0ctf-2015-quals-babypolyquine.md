---
title: '0CTF 2015 Quals -- (Baby)PolyQuine'
date: 2015-05-05 15:23
tags:
  - Python
  - ruby
  - perl
  - C
  - Polyglot
  - Quine
  - CTF
  - 0CTF
  - XCTF
  - Misc
categories:
  - write-ups
---
> Different people see different me.
> But I am always myself.
> <202.112.26.114:12321>
>
> Make the output of your program exactly the same as your source code.
> All 5 correct required to get this flag **(Only need 3 correct for BabyPolyQuine)**
> 
>$python2 --version
> Python 2.7.6
>
> $python3 --version
> Python 3.4.0
>
>$gcc --version
> gcc (Ubuntu 4.8.2-19ubuntu1) 4.8.2
>
> $ruby --version
> ruby 1.9.3p484 (2013-11-22 revision 43786) [x86_64-linux]
>
> $perl --version
> This is perl 5, version 18, subversion 2 (v5.18.2) built for x86_64-linux-gnu-thread-multi
<!-- more -->

The challenge reminds me of [HITCON CTF 2014 -- Polyglot](https://github.com/ctfs/write-ups-2014/tree/master/hitcon-ctf-2014/polyglot), except this time, it want us to write a program, which is not only a polyglot, but also a [quine](http://en.wikipedia.org/wiki/Quine_%28computing%29).  

Well, by searching the answer with the help of the almighty google, we can easily solve the **BabyPolyQuine** challenge by submitting this [program](http://shinh.skr.jp/obf/poly_quine.txt), which pass almost all the languages check -- except for **Python3**.

It seems that Python3 has encounter some syntax error. After changing `def printf(a,*b):p a%b` to `def printf(a,*b):p (a%b)`, Python3 can run it without any error message now, **but it print an extra newline, which doesn't match the challenge's requirement**. So now we're focusing on **how to make both python2 & python3 have the same printing behavior**. After doing some trial & error, I found that for C, Ruby & Perl, they will ignore the line `def printf(a,*b):p (a%b)`, except Python. So we can add some code at that line. 

As for my opinion, I add the following code:
	 
```python 
from sys import* ; p = lambda x:stdout.write(x)
def printf(a,*b):p (a%b)
```

For Python, it will import the sys module, and set a lambda `p` as a `stdout.write()` function. The `stdout.write()` function won't print newline, so python2 & python3 will act like the same. 

The whole program:
```
#include/*
s='''*/<stdio.h>
main(){char*_;/*==;sub _:lvalue{$_}<<s;#';<<s#'''
from sys import* ; p = lambda x:stdout.write(x)
def printf(a,*b):p (a%b)
s
#*/
_=" #include/*%cs='''*/<stdio.h>%cmain(){char*_;/*==;sub _:lvalue{\%c_}<<s;#';<<s#'''%cfrom sys import* ; p = lambda x:stdout.write(x)%cdef printf(a,*b):p (a%%b)%cs%c#*/%c_=%c%s%c;printf(_,10,10,36,10,10,10,10,10,34,_,34,10,10,10,10);%c#/*%cs='''*/%c}//'''#==%c";printf(_,10,10,36,10,10,10,10,10,34,_,34,10,10,10,10);
#/*
s='''*/
}//'''#==
```

After we submit the code, we get the flag as well: `0ctf{"Yields falsehood when preceded by its quotation" yields falsehood when preceded by its quotation}`
