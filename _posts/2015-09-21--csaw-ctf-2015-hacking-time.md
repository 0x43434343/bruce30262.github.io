---
title: 'CSAW CTF 2015 -- Hacking Time'
date: 2015-09-21 12:50
tags:
  - Python
  - CSAW
  - CTF
  - Z3
  - Reversing
  - NES
categories:
  - write-ups
---
**Category:** Reversing
**Points:** 200

This challenge gave us a [NES ROM](https://github.com/ctfs/write-ups-2015/blob/master/csaw-ctf-2015/reverse/hacking-time-200/HackingTime_03e852ace386388eb88c39a02f88c773.nes). After we launch it with NES debugger [FCEUX](http://sourceforge.net/projects/fceultra/?source=typ_redirect), we found out that it eventually want us to input a password with 24 characters in length .

<!-- more -->

We can found that our input was stored at memory address `0x05` ~ `0x1D`. At first I think that the program will just simply take our input and do some `CMP` operation, in order to check the password's correctness. But after doing some runtime analysis, I realize that there's no such operation, which means that the program might use some speical operations to check the password.  

So I decide to set a hardware breakpoint. By using the method which mentioned in [this artical](http://archive.rpgclassics.com/subsites/twit/docs/text/), we can set a **read breakpoint** at address `0x05`, which tells FCEUX to pause the program whenever there's a memory read operation at `0x05`. Once it hit the breakpoint, we can start checking the assembly line by line and try to figure out what operation has been done for the password checking.  

After some reversing and dynamic analysis, I finally figure out the password checking logic and implement it with the following python code:

```python
s1 = "703053A1D3703F64B316E4045F3AEE42B1A137156E882AAB".decode('hex')
s2 = "20AC7A25D79CC21D58D01325966ADC7E2EB4B410CB1DC266".decode('hex')
xs = our_input

def check_password():
	b = 0
	s3 = [-1]*24
	for i in xrange(24):
		a = RotateLeft(xs[i], 3)
		b = RotateRight(b, 2)
		a += b
		a ^= ord(s[i])
		b = a
		a = RotateLeft(a, 4)
		a ^= ord(s2[i])
		s3[i] = a

	for i in xrange(24):
		if(s3[i] != 0):
			return False
	
	return True
```

Now we have the constraint system, time to summon the powerful [Z3](https://github.com/Z3Prover/z3):  

```python
#!/usr/bin/env python

from z3 import *
import sys

s1 = "703053A1D3703F64B316E4045F3AEE42B1A137156E882AAB".decode('hex')
s2 = "20AC7A25D79CC21D58D01325966ADC7E2EB4B410CB1DC266".decode('hex')

def check(xs, s):
    b = BitVecVal(0, 8)
    for i in xrange(24):
        a = RotateLeft(xs[i], 3)
        b = RotateRight(b, 2)
        a += b
        a ^= ord(s1[i])
        b = a
        a = RotateLeft(a, 4)
        a ^= ord(s2[i])
        s.add(a == 0)
    
    if s.check() == sat:
        m = s.model()
        a = ""
        for i in xrange(24):
            a += chr(int(str((m[xs[i]]))))
            #print m[xs[i]]
            #print hex(int(str(m[xs[i]])))
        print a
    else:
        print "unsat"

def solv():
    s = Solver()
    xs = []
    for i in xrange(24):
        x = BitVec("x%d" % i, 8)
        s.add( 33 <= x )
        s.add( x <= 90 )
        xs.append(x)

    check(xs, s)

solv()

```  

Finally, we get the password ( which is also the flag ): `NOHACK4UXWRATHOFKFUHRERX`

