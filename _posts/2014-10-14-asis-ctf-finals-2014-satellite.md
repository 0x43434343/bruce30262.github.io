---
title: ASIS CTF Finals 2014 -- SATELLITE
tags:
  - CTF
  - ASIS
  - Python
  - PPC
categories:
  - write-ups
date: 2014-10-14 16:05:00
---
Description: Connect here and find the flag: `nc asis-ctf.ir 12435`

After we connect to the server, it show us the following message:
<!-- more -->

```
hi all,  You must send a string for each level that would make the literal True 
send "Sattelite"
Sattelite

(¬x2 ∨ ¬x4) ∧ (¬x1 ∨ x2) ∧ (x5 ∨ ¬x1) ∧ (x1 ∨ ¬x1) ∧ (x4 ∨ ¬x5)
```

Hmmm, it's seems like it give us a some kind of expression, which `∨` means **OR**, `∧` means **AND** and `¬` means **NOT**. And we have to send "**something**" to make the literal True. After having some discussion with teammates, I finally understand what we should send. 

Let us define that `x1` is a **variable** and `(¬x2 ∨ ¬x4)` is a **clause**. **The number of the variable depends on how many clause are in the expression**. 

For example, for the following expression: 
```
(¬x2 ∨ ¬x4) ∧ (¬x1 ∨ x2) ∧ (x5 ∨ ¬x1) ∧ (x1 ∨ ¬x1) ∧ (x4 ∨ ¬x5)
```

there are **5** clauses in the expression, so the number of the variable is **5**, which means `x1`~`x5`.

As for the following expression: 
```
(¬x6 ∨ x2) ∧ (x3 ∨ x1) ∧ (¬x5 ∨ ¬x6) ∧ (¬x2 ∨ ¬x7) ∧ (¬x4 ∨ ¬x1) ∧ (x2 ∨ x8) ∧ (¬x6 ∨ ¬x2) ∧ (¬x3 ∨ ¬x7) ∧ (x3 ∨ ¬x6)
```
there are **9** clauses in the expression, so the number of the variable should be **9**, which means `x1`~`x9`, even though `x9` doesn't appear in the expression.

We have to send a string which represent the value of each variable, that make the literal **True**.
For instance, as for the expression 
```
(¬x2 ∨ ¬x4) ∧ (¬x1 ∨ x2) ∧ (x5 ∨ ¬x1) ∧ (x1 ∨ ¬x1) ∧ (x4 ∨ ¬x5)
```
we can send `00000`, which makes `(¬0 ∨ ¬0) ∧ (¬0 ∨ 0) ∧ (0 ∨ ¬0) ∧ (0 ∨ ¬0) ∧ (0 ∨ ¬0)` equals **True**. 

And for the expression 
```
(¬x6 ∨ x2) ∧ (x3 ∨ x1) ∧ (¬x5 ∨ ¬x6) ∧ (¬x2 ∨ ¬x7) ∧ (¬x4 ∨ ¬x1) ∧ (x2 ∨ x8) ∧ (¬x6 ∨ ¬x2) ∧ (¬x3 ∨ ¬x7) ∧ (x3 ∨ ¬x6)
```
both `110000000` and `110000001` will all make the literal True, since `x9` doesn't appear in the expression.

So we finally know what should we send to pass the level and get the flag, time to write some code. For this challenge I decide to write a python script to calculate the answer and send it automatically. 

I assume that the number of variable won't larger than 20 ( just a wild guess, and luckily, I was right ^_^ ). So I decide to calculate the answer by brute-forcing all the possible string. If there are 5 variables, I just went through all the string from `00000` ~ `11111`. The time complexity is `2^n`, which isn't very effective, but it can still calculate the right answer in less than 5 seconds.

So here is what I'm going to do:
1. parse the input expression, convert it into a string that `eval` can recognize & evaluate the result.
2. run through `00...0` to `11...1`, substitute variables with `0` or `1`
3. use `eval` to evaluate the result. If it's `1`, send the answer, or else run the next string.
  
For example, the input expression is 
```
(¬x2 ∨ ¬x4) ∧ (¬x1 ∨ x2) ∧ (x5 ∨ ¬x1) ∧ (x1 ∨ ¬x1) ∧ (x4 ∨ ¬x5)
```
After the parsing function, the string will be like this:
```
(~2 | ~4) & (~1 | 2) & (5 | ~1) & (1 | ~1) & (4 | ~5)
```
and then run through `00...0` to `11...1`, substitute `1`,`2`...to `0` or `1`. To ensure the result will be only `1` or `0`, each `0` & `1` will do the `& 0x1` operation ( convert operands to 1 bit ). So the final evaluate string will be: 
```
(~0 & 0x1 | ~0 & 0x1) & (~0 & 0x1 | 0 & 0x1) & (0 & 0x1 | ~0 & 0x1) & (0 & 0x1 | ~0 & 0x1) & (0 & 0x1 | ~0 & 0x1)
```

```python sat.py
from socket import *
from struct import *

def string_to_expression(input_str):

	# OR, AND & NOT's ascii code might be weird and should be treated as special case
	# 226 136 168 -> OR (ascii: 124)
	# 226 136 167 -> AND (ascii: 38)
	# 194 172 -> NOT (ascii: 126)	
	
	expression = [] # list for storing the expression's ascii code & variable id
	cur_num = 0 # calculate single variable id
	max_num = 0 # total variable number
	inCal = False
		
	for c in input_str:
		asc = ord(c)
		
		if c.isdigit() == True:
			if inCal == False:
				inCal = True

			cur_num = 10*cur_num + asc - 48
				
		else:
			if inCal == True:
				inCal = False
				expression.append(cur_num)
				cur_num = 0
				
			if asc == 226 or asc == 136 or asc == 194 or asc == 120: #ignore, continue
				continue
			elif asc == 168: # OR
				expression.append(124)
			elif asc == 167: # AND
				expression.append(38)
			elif asc == 172: # NOT
				expression.append(126)
			elif asc == 10: # end of expression, break
				break;
			elif asc == 40: # '(', count variable number
				max_num += 1
				expression.append(asc)
			else:
				expression.append(asc)

	return expression, max_num


def carry(x_list, size):
	# from 0000 to 0001, 0001 to 0010.....
	x_list[size-1] += 1
	for i in range(size-1, -1, -1):
		x_list[i-1] += x_list[i]/2
		x_list[i] %= 2
	return x_list

def cal_ok(eval_list, cur_max):
	index_list = [[] for i in range(cur_max)] # index list that record each variable's position
	x_list = [0]*cur_max

	for index,item in enumerate(eval_list):
		if item <= cur_max:
			index_list[item-1].append(index)
	
	cnt = 2**cur_max

	for i in range(cnt):
		for number in range(cur_max):
			for index in index_list[number]:
				eval_list[index] = x_list[number]
		
		eval_str = ""
		for item in eval_list:
			if item == 0 or item == 1:
				eval_str += str(item)
				eval_str += str(' & 0x1 ')
			else:
				eval_str += chr(item)
		
#		print "calculating: " + eval_str
#		print "result: " + str(eval(eval_str))
		
		if eval(eval_str) == 1: # found the answer!
			return "".join(str(c) for c in x_list)
		else: # add 1 bit and run the next string
			carry(x_list, cur_max)


sock = socket(AF_INET, SOCK_STREAM) #create socket (IP, TCP)
sock.connect(("asis-ctf.ir" , 12435))

print sock.recv(1024)
sock.send("Sattelite\n")

while True:
	res = sock.recv(1024)
	print res
	
	if "ASIS" in res: # get the flag
		break

	eval_list, cur_max = string_to_expression(res) # convert input expression to list
	eval_str = cal_ok(eval_list, cur_max) # calculate the right answer
	print "ans: " + eval_str
	sock.send(eval_str+'\n')
	ok = sock.recv(1024)
	print ok

	if "OK" not in ok:
		break	

sock.close()
```

Finally, we get the flag!

![sat.PNG](http://user-image.logdown.io/user/10044/blog/9742/post/237394/9GgabEuXTOSzTIYSEpmw_sat.PNG)

flag: `ASIS_5b5e15ec25479ac8b743c6e818d75464`