---
title: 0CTF 2015 Quals -- geo-newbie
tags:
  - Python
  - PPC
  - 0CTF
  - XCTF
  - Misc
  - CTF
categories:
  - write-ups
date: 2015-05-05 14:26:00
---
> Talentyange gives lots of tedious apks and you know how bad he is now. Let's try some interesting geography knowledge.
> 
>   nc 202.112.26.111  29995 /  nc 202.112.28.118 29995
<!-- more -->

So basically we just connect to the server, and it will ask us a bunch of questions about geography. We'll have to pass 3 levels (75 questions) to get the flag.  

For level0, it asked us for the [alpha2 code](http://en.wikipedia.org/wiki/ISO_3166-1_alpha-2) of a country. For example, if they gave us "JAPAN", we'll have to send "JP" back to the server. To pass this level, I download a json file from the internet and use it as the alpha2 code database. Just extract the country name and send the corresponding alpha2 code. After answering 20 questions, we pass level0.  

For level1, it gave us a location (ex. Mount Fuji), and we'll have to answer the country (in alpha2 code format, ex. **Mount Fuji** --> **JP**) that contains the location. To pass the level, I use the [google API](http://maps.googleapis.com/maps/api/geocode/json) to solve the problems. Extract the location and pass it as the "address" parameter, the API will respond with a json format response. Parse the response and get the correct country 
name. Notice that sometimes google API will respond a wrong country(mostly it respond US instead of the correct country), so we will need to handle some special cases (by hard-code the correct answer in the script). This level has 50 questions, solve them all and we'll be able to reach level2.

And for the last level, the server gave us a river or a moutain (ex. Congo River, Andes Mountains....etc), and we'll have to answer all the countries that the given river/mountain run across. To pass this level, I just hard-code all the answer in the script. First we'll have to reach level2 several times, collect as much rivers/mountains as we can, then google the answer, hard-code them in the script. I add some conditions in my script. If the program encounters a river/mountain that it already has the answer in the script, it will send the answer to the server. Or else, it'll switch to the interactive mode , and I'll take control of the situation -- by google & send the answer with my own hand ( you know, speed mode activated ! )

Here's the script I used for solving the challenge:

```python
# -*- coding: utf-8 -*-
from pwn import *
import json
import re
import time
import urllib2
import urllib

url = 'http://maps.googleapis.com/maps/api/geocode/json'
values = {}
values['sensor'] = "false"

HOST = "202.112.26.111"
PORT = 29995
TIME = 0.8

with open('level0.json') as alpha2_file:
    alpha2 = json.load(alpha2_file)

r = remote(HOST, PORT)

def get_alpha2(s):
    global alpha2
    for country in alpha2:
        name = country["Name"].encode('utf-8')
        if name.decode('utf-8') == s.decode('utf-8'):
            return country["Code"]  

def solve_level1(s):
	if s == "Naples":
		return "IT"
	if s == "Vancouver":
		return "CA"
	if s == "Volga":
		return "RU"
	if s == "Lego":
		return "DK"
	if s == "Hyde Park":
		return "GB"
	if s == "Alexandria":
		return "EG"
	if s == "Melboume":
		return "AU"
	if s == "Rickshaw capital of the world":
		return "BD"
	if s == "Mount Olympus":
		return "GR"
		
	global url, values
	values['address'] = s
	data = urllib.urlencode(values)
	resp = json.load(urllib2.urlopen(url+'?'+data))

	for c in resp["results"][0]["address_components"]:
		if c["types"][0] == "country":
			print c["short_name"]
			return c["short_name"]

r.recvuntil("Tell me the Alpha-2 code of country.")

for i in xrange(20):
    res = r.recv(1024)
    print "res", res
    #country = re.search("--- Round (\d+) ---\n(\S+ ):", res).groups(0)[1]
    country = res[res.index("-\n")+2:res.index(":"):]
    print "now:", country
    ans = get_alpha2(country)
    print "ans:", ans
    r.send(ans+'\n')
    time.sleep(TIME)

for i in xrange(20, 70):
    res = r.recv(1024)
    print "res", res
    country = res[res.index("-\n")+2:res.index(":"):]
    print "now:", country
    ans = solve_level1(country)
    print "ans:", ans
    r.send(ans+'\n')
    time.sleep(TIME)

# level2, not all the case
Congo_River = ["AO", "BI", "CM", "CF", "CD", "GA", "CG", "RW", "TZ", "ZM"]
Alps = ["CH", "AT", "LI", "DE", "IT", "SI", "FR"]
Andes = ["AR", "BO", "CL", "CO", "EC", "PE", "VE"]
Himalayas = ["BT", "NP", "CN", "IN", "PK"]
Mekong_River = ["CN", "MM", "LA", "TH", "KH", "VN"]
Rocky_Mountain = ["CA", "US"]
Parana_River = ["AR", "BR", "PY"]
Nile = ["ET", "SD", "EG", "UG", "CD", "KE", "TZ", "RW", "SS", "ER", "BI"]
Apennine = ["IT", "SM"]

for i in xrange(70, 75):
	res = r.recv(1024)
	print "res", res

	if "Congo River" in res:
		for index, c in enumerate(Congo_River):
			print "send:", c
			r.send(c+'\n')
			time.sleep(TIME)
			if index == len(Congo_River)-1: break
			print r.recv(1024)
	if "Alps" in res:
		for index, c in enumerate(Alps):
			print "send:", c
			r.send(c+'\n')
			time.sleep(TIME)
			if index == len(Alps)-1: break
			print r.recv(1024)
	if "Andes" in res:
		for index, c in enumerate(Andes):
			print "send:", c
			r.send(c+'\n')
			time.sleep(TIME)
			if index == len(Andes)-1: break
			print r.recv(1024)
	if "Himalayas" in res:
		for index, c in enumerate(Himalayas):
			print "send:", c
			r.send(c+'\n')
			time.sleep(TIME)
			if index == len(Himalayas)-1: break
			print r.recv(1024)
	if "Mekong River" in res:
		for index, c in enumerate(Mekong_River):
			print "send:", c
			r.send(c+'\n')
			time.sleep(TIME)
			if index == len(Mekong_River)-1: break
			print r.recv(1024)
	if "Rocky Mountain" in res:
		for index, c in enumerate(Rocky_Mountain):
			print "send:", c
			r.send(c+'\n')
			time.sleep(TIME)
			if index == len(Rocky_Mountain)-1: break
			print r.recv(1024)
	if "Nile" in res:
		for index, c in enumerate(Nile):
			print "send:", c
			r.send(c+'\n')
			time.sleep(TIME)
			if index == len(Nile)-1: break
			print r.recv(1024)
	if "Parana River" in res:
		for index, c in enumerate(Parana_River):
			print "send:", c
			r.send(c+'\n')
			time.sleep(TIME)
			if index == len(Parana_River)-1: break
			print r.recv(1024)
	if "Apennine Mountains" in res:
		for index, c in enumerate(Apennine):
			print "send:", c
			r.send(c+'\n')
			time.sleep(TIME)
			if index == len(Apennine)-1: break
			print r.recv(1024)
	else: # solve by hand
		r.interactive()
	time.sleep(TIME)
```

After answering all the questions, we get the flag: `0CTF{eNj0y_geography_l0v3_7hE_w0lRd}`