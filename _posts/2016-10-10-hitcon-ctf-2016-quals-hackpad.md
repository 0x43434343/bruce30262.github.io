---
title: HITCON CTF 2016 Quals -- Hackpad
tags:
  - Python
  - CTF
  - HITCON
  - Crypto
  - Forensic
  - padding_oracle_attack
categories:
  - write-ups
date: 2016-10-10 16:08:00
---
**Category:** Crypto & Forensics
**Points:** 150

<!-- more -->  

I did not look at this challenge at first, until I found that many teams have already solved this one except us, so I decide to give it a try :P  
  
It first gave us a pcap file. Several of my teammates have already extract some information before I started to solve the challenge. To be brief, these packets contain the following message:

First is the encrypted secret:
```
encrypt(secret):
3ed2e01c1d1248125c67ac637384a22d997d9369c74c82abba4cc3b1bfc65f026c957ff0feef61b161cfe3373c2d9b905639aa3688659566d9acc93bb72080f7e5ebd643808a0e50e1fc3d16246afcf688dfedf02ad4ae84fd92c5c53bbd98f08b21d838a3261874c4ee3ce8fbcb96628d5706499dd985ec0c13573eeee03766f7010a867edfed92c33233b17a9730eb4a82a6db51fa6124bfc48ef99d669e21740d12656f597e691bbcbaa67abe1a09f02afc37140b167533c7536ab2ecd4ed37572fc9154d23aa7d8c92b84b774702632ed2737a569e4dfbe01338fcbb2a77ddd6990ce169bb4f48e1ca96d30eced23b6fe5b875ca6481056848be0fbc26bcbffdfe966da4221103408f459ec1ef12c72068bc1b96df045d3fa12cc2a9dcd162ffdf876b3bc3a3ed2373559bcbe3f470a8c695bf54796bfe471cd34b463e9876212df912deef882b657954d7dada47
```
And the packets that contain the information of the decrypt message:
```
msg=00000000000000000000000000000000997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = aa85a4e0adbd34c287af2d20da4453c9

msg=0000000000000000000000000000d903997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = 9f5b543c64d3e384078fdd8cf4b2ce6d

msg=00000000000000000000000000efd802997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = c68dda2cc0d9907bc7252b53a447b2ce

msg=00000000000000000000000007e8df05997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = 650713f94eae0ecdfa4e527745dd2591
................................................
................................................
msg=0000ce71616536683d0ed00c0de2d50f997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = 6d09e40852ecf180281d504b7718d12d

msg=00b3cf70606437693c0fd10d0ce3d40e997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = f1290186a5d0b1ceab27f4e77c0c5d68

msg=67acd06f7f7b28762310ce1213fccb11997d9369c74c82abba4cc3b1bfc65f02
md5(decrypt(msg)) = d41d8cd98f00b204e9800998ecf8427e
................................................
................................................
```

Looks like someone was sending a bunch of encrypted message, and try to let the server decrypt the message for him. I also found that we can split the encrypted message by every 32 character:
```
encrypt(secret):
msg=
3ed2e01c1d1248125c67ac637384a22d
997d9369c74c82abba4cc3b1bfc65f02 <-- here!
6c957ff0feef61b161cfe3373c2d9b90
5639aa3688659566d9acc93bb72080f7
e5ebd643808a0e50e1fc3d16246afcf6
88dfedf02ad4ae84fd92c5c53bbd98f0
8b21d838a3261874c4ee3ce8fbcb9662
8d5706499dd985ec0c13573eeee03766
f7010a867edfed92c33233b17a9730eb
4a82a6db51fa6124bfc48ef99d669e21
740d12656f597e691bbcbaa67abe1a09
f02afc37140b167533c7536ab2ecd4ed
37572fc9154d23aa7d8c92b84b774702
632ed2737a569e4dfbe01338fcbb2a77
ddd6990ce169bb4f48e1ca96d30eced2
3b6fe5b875ca6481056848be0fbc26bc
bffdfe966da4221103408f459ec1ef12
c72068bc1b96df045d3fa12cc2a9dcd1
62ffdf876b3bc3a3ed2373559bcbe3f4
70a8c695bf54796bfe471cd34b463e98
76212df912deef882b657954d7dada47
```
Notice the line that marked "here!", the string is actually identical to sencond half of `00000000000000000000000000000000997d9369c74c82abba4cc3b1bfc65f02`. 

I suck at crypto, so at first I just keep inspecting the decrypt message info, hoping that I can find some special pattern so I can use it to decrypt the secret.  And of course I failed miserably, until I notice that some of the decrypt request were failed -- the server response with the code 500 ( or 403 ) instead of 200.  And that's the moment I started to think "Wait a minute...this looks familiar...isn't this the pattern of the **padding oracle attack** ?"  And so I start googling about the padding oracle attack.

And guess what ? It **IS** the padding oracle attack !  

So with the help of [this writeup](http://mslc.ctf.su/wp/codegate-ctf-2011-crypto-400/) posted by MSLC, I figured out that to decrypt the message `997d9369c74c82abba4cc3b1bfc65f02` (let's call it `C1`), first we'll have to find the value of `AES_Decrypt(C1)`, which can be done by xor-ing the value of
```
67acd06f7f7b28762310ce1213fccb11 (last attacker's ciphertext)
```
and
```
10101010101010101010101010101010 (padding)
```

After we get the value of `AES_Decrypt(C1)`, we can decrypt `C1` by doing `AES_Decrypt(C1) xor C0`. `C0` is the first block of the ciphertext, which is 
```
3ed2e01c1d1248125c67ac637384a22d
```
in this case.  

And so I wrote a script to decrypt the whole message:
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import subprocess
import sys

def myexec(cmd):
    return subprocess.check_output(cmd, shell=True)

# "cat ./ggg": print out all the last attacker ciphertext
resp = myexec("cat ./ggg").split("\n")
del resp[-1]

temp = []
for i, c in enumerate(resp):
    if i == 0: # first line is encrypt(secret), ignore
        continue
    d = c.split("=")[1].strip()
    assert len(d) == 64
    temp.append(d)

last_c = []
enc = []
for c in temp:
    last_c.append(c[0:32])
    enc.append(c[32::])

enc.insert(0, "3ed2e01c1d1248125c67ac637384a22d")

def fix_len(s):
    if len(s) % 2 == 1:
        s = "0"+s
    assert len(s) == 32
    return s

cnt = 0
plain = ""
for c in last_c:
    c = c.decode('hex')
    pad = "10101010101010101010101010101010".decode('hex')
    s = 0
    for c1, c2 in zip(pad, c):
        s |= ord(c1)^ord(c2)
        s<<=8
    sss = hex(s>>8)[2:-1:]
    sss = fix_len(sss)

    s = 0
    sss = sss.decode('hex')
    eee = enc[cnt].decode('hex')
    for c1, c2 in zip(eee, sss):
        s |= ord(c1)^ord(c2)
        s<<=8
    f = hex(s>>8)[2:-1:]
    f = fix_len(f)

    plain += f.decode('hex')
    cnt += 1

print plain

```
`ggg` is a file that store the value of `encrypt(secret)` and all the last attacker's ciphertext ( grab it from pcap file with the help of `strings` & `grep` )

And so we have the decrypted message:
```
In cryptography, a padding oracle attack is an attack which is performed using the padding of a cryptographic message.
hitcon{H4cked by a de1ici0us pudding '3'}
In cryptography, variable-length plaintext messages often have to be padded (expanded) to be compatible with the underlying cryptographic primitive.
```

flag: `hitcon{H4cked by a de1ici0us pudding '3'}`
