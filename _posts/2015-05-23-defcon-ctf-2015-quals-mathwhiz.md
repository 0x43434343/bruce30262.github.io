---
title: 'DEFCON CTF 2015 Quals -- mathwhiz'
date: 2015-05-23 22:39
tags:
  - Python
  - DEFCON
  - CTF
  - PPC
categories:
  - write-ups
---
**Category:** Baby's First
**Points:** 1
> mathwhiz_c951d46fed68687ad93a84e702800b7a.quals.shallweplayaga.me:21249

<!-- more -->

The challenge's pretty simple. The service will ask you a bunch of math problems(**1000 actually**), all you need to do is to answer all of them and you'll get the flag. Notice that some of the questions contains some tricky input, like **"ONE + TWO = ?"**, **"[1 + 2] + 4=?"**......etc.  

```python
from pwn import *
import string

HOST = "mathwhiz_c951d46fed68687ad93a84e702800b7a.quals.shallweplayaga.me"
PORT = 21249

r = remote(HOST, PORT)

LOG = True

d = dict()
d['{'] = '('
d['}'] = ')'
d['['] = '('
d[']'] = ')'

def my_recvuntil(delim):
    res = ""
    while delim not in res:
        c = r.recv(1)
        sys.stdout.write(c)
        res += c
    return res

cnt = 0
while True:
    print "Round:", cnt
    cnt += 1
    s = my_recvuntil("=\n")
    term = s[0:s.index('=\n'):]
    print "term:", term
    term_list = list(term)
    for index,c in enumerate(term_list):
        if c in d:
            term_list[index] = d[c]
    final_term = ''.join(x for x in term_list)
    
    final_term = final_term.replace("ONE", "1")
    final_term = final_term.replace("TWO", "2")
    final_term = final_term.replace("THREE", "3")
    final_term = final_term.replace("FOUR", "4")
    final_term = final_term.replace("FIVE", "5")
    final_term = final_term.replace("SIX", "6")
    final_term = final_term.replace("SEVEN", "7")
    final_term = final_term.replace("EIGHT", "8")
    final_term = final_term.replace("NINE", "9")
    final_term = final_term.replace("^", "**")
    
    print "Final:", final_term
    ans = eval(final_term)
    print "ans:", ans
    r.sendline(str(ans))
 
```

Flag: `Farva says you are a FickenChucker and you'd better watch Super Troopers 2`
