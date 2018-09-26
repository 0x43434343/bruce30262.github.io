---
title: 'VolgaCTF 2015 Quals -- math problem'
date: 2015-05-22 13:49
tags:
  - Python
  - CTF
  - VolgaCTF
  - PPC
categories:
  - write-ups
---

**Category:** PPC
**Points:** 300
> nc mathproblem.2015.volgactf.ru 8888

This problem remind me of [HITCON CTF 2014 -- 24](https://github.com/ctfs/write-ups-2014/tree/master/hitcon-ctf-2014/24)

<!-- more -->

The server gave us 5 numbers `v1`, `v2`, `v3`, `v4` & `v5`, and ask us to use `+`, `-`, `*`, `/`, `(` & `)` to do some operation with `v1`, `v2`, `v3` & `v4`, and make it equal to `v5`

The solution is pretty simple: since it gave us a lot of time to solve a round, we can easily beat the challenge by brute-forcing all the possible combinations of operators & operands

```python
from pwn import *
import re
import sys
import itertools

HOST="mathproblem.2015.volgactf.ru"
PORT=8888

r = remote(HOST, PORT)

def solve(numbers, answer):
    ops = "+ - * /".split(" ")
    wrap = ["", "(", ")"]
    
    iterN = list(itertools.permutations(numbers, 4))
    iterO = list(itertools.product(ops, repeat=3))
    iterW = list(itertools.product(wrap, repeat=8))

    for number in iterN:
        for op in iterO:
            for w in iterW:
                expr = w[0]+number[0]+w[1]+op[0]+w[2]+number[1]+w[3]+op[1]+w[4]+number[2]+w[5]+op[2]+w[6]+number[3]+w[7]
                try:
                    val = eval(expr)
                    if val == answer:
                        return expr
                    else:
                        continue
                except:
                    pass
cnt = 0
while True:
    if cnt == 30:
        r.interactive()

    s = r.recvuntil("Solve!\n")
    print s
    s = r.recv(1024)
    print s
    temp = s.split(" ")
    numbers = [temp[i] for i in xrange(4)]
    answer = int(temp[5])
    print numbers, answer
    ans = solve(numbers, answer)
    print ans
    r.send(ans+'\n')
    cnt += 1

```

Flag: `{you_count_as_fast_as_a_calculator}`

