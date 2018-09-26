---
title: ASIS CTF Finals 2014 -- How much exactly + Lottery
tags:
  - CTF
  - ASIS
  - Web
  - Misc
categories:
  - write-ups
date: 2014-10-14 15:15:00
---
Both challenges are kind of easy, so I decide to put their writeups together.
<!-- more -->

# How much exactly?
Description: 4046925: How much the exact IM per year?

just do some search on the internet, and we'll find this [link](https://archive.org/stream/Untangling_the_Web/Untangling_the_Web_djvu.txt) 

".....Instant messaging generates five billion messages a day (750GB), or **274 Terabytes a year**."

so the flag will be ASIS_md5(274) = `ASIS_d947bf06a885db0d477d707121934ff8`


# Lottery

Description: Go here: http://asis-ctf.ir:12437

After entering the site we'll find a message at the front page

```
The 1234567890 th visitor, the prize awarded.
Anyone who has visited our site is the 1234567890 th Special prizes are awarded. 
You have visited us already 
You are the 1496 visitor
Don't hack cookies, we are alive :)
```

well, let's go check the cookie shall we ;)

and so we found a cookie name `Visitor`, which contains the value:
```
MTQ5NjoxNDE1ZGI3MGZlOWRkYjExOWUyM2U5YjI4MDhjZGUzOA%3D%3D
```

if we url-decode `%3D` the result will be `=`, so the cookie actually contains a base64 encode string. After we decode the whole string, it shows `1496:1415db70fe9ddb119e23e9b2808cde38`.

After doing some research we found that `1415db70fe9ddb119e23e9b2808cde38` is actually `md5(1496)`. So the challenge is quite simple: we just need to modify the cookie value to `base64_encode(1234567890:md5(1234567890))`, then we'll get the flag.

So just type the following script into the url bar (I'm using chrome):
```
javascript:document.cookie="Visitor=MTIzNDU2Nzg5MDplODA3ZjFmY2Y4MmQxMzJmOWJiMDE4Y2E2NzM4YTE5Zg=="
```
Refresh the page, then the front page will show us the flag :)

flag: `ASIS_9f1af649f25108144fc38a01f8767c0c`