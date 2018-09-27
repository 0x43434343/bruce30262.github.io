---
title: ASIS CTF Finals 2014 -- TicTac
layout: single
comments: true
share: true
related: true
author_profile: true
permalink: "/:title/"
tags:
- CTF
- ASIS
- Python
- Forensic
categories:
- write-ups
date: '2014-10-15 02:41:00 +0000'
---

Description:  Find flag in [this](http://asis-ctf.ir/tasks/tictac_4c56077190984fde63900b3ba14d11dd) file
<!-- more -->

After extracting data in the compressed file, we found a .pcap file. Analyze the file with Wireshark, we found there're lots of ICMP packets in it. After checking those packets with eyes wide-open, we found some interesting stuff : one of the ICMP packet contains the following data: `7069636b206d653a204153`

At first I just think that this might be a part of a md5-encrypted string. But then I found that other packets contains similar data, too. I found that there's data like `7069636b206d653a203635`, `7069636b206d653a203965`...etc. Notice that there's a slight difference between those strings: **their last 4 characters are different**.

So I take a good look at those strings, and found that those were actually a **string represent as hex values**. If we convert those hex values into characters, `7069636b206d653a20` will be `pick me:`. So the string `7069636b206d653a204153` will be `pick me: AS`. This discovery got my attention, so I kept searching data that contains `7069636b206d653a20`, and found that not only ICMP, but also IPv4 protocol contains these data. So I deicided to use `strings` and `grep` to get those data out of the file, and here's the result:

```bash
root@kali:~/Desktop# strings tictac.pcap | grep "7069636b206d653a20"
7069636b206d653a204153`
7069636b206d653a204153`
7069636b206d653a204953d
7069636b206d653a204953
7069636b206d653a205f36l
7069636b206d653a206435t
7069636b206d653a206435
7069636b206d653a203461l
7069636b206d653a203461
7069636b206d653a203637
7069636b206d653a203637
7069636b206d653a203635`
7069636b206d653a203635`
7069636b206d653a203965`
7069636b206d653a203965`
7069636b206d653a203435d
7069636b206d653a206564l
W27069636b206d653a206265`
7069636b206d653a203633t
7069636b206d653a206262
7069636b206d653a206639X
7069636b206d653a203039`
7069636b206d653a203039`
7069636b206d653a206536l
Z47069636b206d653a206231`
7069636b206d653a203833`
7069636b206d653a203833`
7069636b206d653a206120d
7069636b206d653a206120
7069636b206d653a20p
7069636b206d653a20
root@kali:~/Desktop#
```
Filter out the duplicate one, the final result will be like this:
```
7069636b206d653a204153
7069636b206d653a204953
7069636b206d653a205f36
7069636b206d653a206435
7069636b206d653a203461
7069636b206d653a203637
7069636b206d653a203635
7069636b206d653a203965
7069636b206d653a203435
7069636b206d653a206564
7069636b206d653a206265
7069636b206d653a203633
7069636b206d653a206262
7069636b206d653a206639
7069636b206d653a203039
7069636b206d653a206536
7069636b206d653a206231
7069636b206d653a203833
7069636b206d653a206120
```

We can see that there're totally 19 lines of data. Each data contains 2 characters in the flag, which means there're totaly 38 characters. The flag's format is `ASIS_md5(xxx)`, which is a 37-characters string, so we can expect that if we combine the last 2 characters in each data, we'll know what the flag is. To do this, just write a python script and let the program do the rest.

```python
f = open("data", "r")

flag = ""

for line in f:
	flag += chr(int(line[18:20],16))	
	flag += chr(int(line[20:22],16))
	print flag

```

Boom! CTF ;)

flag: `ASIS_6d54a67659e45edbe63bbf909e6b183a`