var store = [{
        "title": "CSAW CTF 2014 -- Exploitation 200 pybabbies",
        "excerpt":"CSAW CTF 2014 is the second CTF contest I’ve attended ( the first one was the HITCON CTF 2014 ) . Since this is the first time I’ve actually solved something in the contest, I decide to post my first own writeup . I’ve solved 4 challenges in the contest...","categories": ["write-ups"],
        "tags": ["CTF","CSAW","Pwnable","Python"],
        "url": "http://0.0.0.0:4000/csaw-ctf-2014-exploitation-200-pybabbies/",
        "teaser":null},{
        "title": "CSAW CTF 2014 -- Exploitation 400 saturn",
        "excerpt":"First the challenge gave us a binary file (ELF for Intel-386). But we can’t execute it, cause we don’t have the required shared library “libchallengeresponse.so”. So we will have to launch IDA Pro to see what’s going on within the program. After analyzing the program ( praise the powerful F5...","categories": ["write-ups"],
        "tags": ["CTF","CSAW","Python","Pwnable"],
        "url": "http://0.0.0.0:4000/csaw-ctf-2014-exploitation-400-saturn/",
        "teaser":null},{
        "title": "ASIS CTF Finals 2014 -- How much exactly + Lottery",
        "excerpt":"Both challenges are kind of easy, so I decide to put their writeups together. How much exactly? Description: 4046925: How much the exact IM per year? just do some search on the internet, and we’ll find this link “…..Instant messaging generates five billion messages a day (750GB), or 274 Terabytes...","categories": ["write-ups"],
        "tags": ["CTF","ASIS","Web","Misc"],
        "url": "http://0.0.0.0:4000/asis-ctf-finals-2014-how-much-exactly-lottery/",
        "teaser":null},{
        "title": "ASIS CTF Finals 2014 -- SATELLITE",
        "excerpt":"Description: Connect here and find the flag: nc asis-ctf.ir 12435 After we connect to the server, it show us the following message: hi all, You must send a string for each level that would make the literal True send \"Sattelite\"Sattelite(¬x2 ∨ ¬x4) ∧ (¬x1 ∨ x2) ∧ (x5 ∨ ¬x1)...","categories": ["write-ups"],
        "tags": ["CTF","ASIS","Python","PPC"],
        "url": "http://0.0.0.0:4000/asis-ctf-finals-2014-satellite/",
        "teaser":null},{
        "title": "ASIS CTF Finals 2014 -- TicTac",
        "excerpt":"Description: Find flag in this file After extracting data in the compressed file, we found a .pcap file. Analyze the file with Wireshark, we found there’re lots of ICMP packets in it. After checking those packets with eyes wide-open, we found some interesting stuff : one of the ICMP packet...","categories": ["write-ups"],
        "tags": ["CTF","ASIS","Python","Forensic"],
        "url": "http://0.0.0.0:4000/asis-ctf-finals-2014-tictac/",
        "teaser":null},{
        "title": "SCTF 2014 -- Pwn200",
        "excerpt":"SCTF is a CTF contest hold by XCTF ( seems like a Chinese version’s CTFtime.org ). Teaming up with my labmates, we have a lot of fun solving the challenges, and scored 2161 pts with the final rank 13/659. In Pwn200, they gave us a binary file and a libc.so....","categories": ["write-ups"],
        "tags": ["Pwnable","XCTF","SCTF","CTF"],
        "url": "http://0.0.0.0:4000/sctf-2014-pwn200/",
        "teaser":null},{
        "title": "SCTF 2014 -- Pwn400",
        "excerpt":"Similar with Pwn200, Pwn400 gave us a binary file, but no libc.so. Open it with IDA Pro and analyze it, we found some information: First, there’s a data structure ( let’s call it node ) which look like this: struct node{ node *this; // the address of this node node...","categories": ["write-ups"],
        "tags": ["Pwnable","XCTF","SCTF","Python","CTF","heap","shellcode"],
        "url": "http://0.0.0.0:4000/sctf-2014-pwn400/",
        "teaser":null},{
        "title": "SCTF 2014 -- Code400",
        "excerpt":"Code400 gave us a python script ``` python code400.pyimport jsonimport hashlibimport osimport base64from Crypto.Cipher import AES fp = open(“secret.json”, “r”)secret = json.load(fp)fp.close() if type(secret[“the answer to life the universe and everything”]) != type(u”77”): destroy_the_universe() answer = hashlib.sha1(secret[“the answer to life the universe and everything”]).hexdigest()[0:16]key = hashlib.sha1(secret[“Don’t google what it is”]).digest()[0:6]...","categories": ["write-ups"],
        "tags": ["Python","CTF","PPC","XCTF","SCTF","Crypto","CPP"],
        "url": "http://0.0.0.0:4000/sctf-2014-code400/",
        "teaser":null},{
        "title": "0CTF 2015 Quals -- (Baby)PolyQuine",
        "excerpt":"Different people see different me.But I am always myself.&lt;202.112.26.114:12321&gt; Make the output of your program exactly the same as your source code.All 5 correct required to get this flag (Only need 3 correct for BabyPolyQuine) $python2 –versionPython 2.7.6 $python3 –versionPython 3.4.0 $gcc –versiongcc (Ubuntu 4.8.2-19ubuntu1) 4.8.2 $ruby –versionruby 1.9.3p484 (2013-11-22...","categories": ["write-ups"],
        "tags": ["Python","ruby","perl","C","Polyglot","Quine","CTF","0CTF","XCTF","Misc"],
        "url": "http://0.0.0.0:4000/0ctf-2015-quals-babypolyquine/",
        "teaser":null},{
        "title": "0CTF 2015 Quals -- geo-newbie",
        "excerpt":"Talentyange gives lots of tedious apks and you know how bad he is now. Let’s try some interesting geography knowledge. nc 202.112.26.111 29995 / nc 202.112.28.118 29995 So basically we just connect to the server, and it will ask us a bunch of questions about geography. We’ll have to pass...","categories": ["write-ups"],
        "tags": ["Python","PPC","0CTF","XCTF","Misc","CTF"],
        "url": "http://0.0.0.0:4000/0ctf-2015-quals-geo-newbie/",
        "teaser":null},{
        "title": "BackdoorCTF 2015 -- Binary + Misc",
        "excerpt":"BackdoorCTF 2015For me, this is a challenge for CTF beginners. Most of the challenges are easy to solve, although some of them require some “imagination”… In this writeup, I’ll post the solutions of all the binary challenges and the misc challenges that I solved in the CTF. Binary echo Basic...","categories": ["write-ups"],
        "tags": ["BackdoorCTF","CTF","Python","ruby","Pwnable","PPC","Misc","Forensic"],
        "url": "http://0.0.0.0:4000/backdoorctf-2015-binary-misc/",
        "teaser":null},{
        "title": "VolgaCTF 2015 Quals -- math problem",
        "excerpt":"Category: PPCPoints: 300 nc mathproblem.2015.volgactf.ru 8888 This problem remind me of HITCON CTF 2014 – 24 The server gave us 5 numbers v1, v2, v3, v4 &amp; v5, and ask us to use +, -, *, /, ( &amp; ) to do some operation with v1, v2, v3 &amp; v4,...","categories": ["write-ups"],
        "tags": ["Python","CTF","VolgaCTF","PPC"],
        "url": "http://0.0.0.0:4000/volgactf-2015-quals-math-problem/",
        "teaser":null},{
        "title": "VolgaCTF 2015 Quals -- my little pwnie",
        "excerpt":"Category: PwnPoints: 250 Just another pwn task. Break in!nc pwnie.2015.volgactf.ru 7777my_little_pwnie I solve the challenge after the end of the CTF, because I think this is a great challenge for practicing format string and sprintf BOF vulnerability. Special thanks to Lays for putting the exploit on the trello and let...","categories": ["write-ups"],
        "tags": ["VolgaCTF","CTF","Python","Pwnable","assembly","format_string","BOF"],
        "url": "http://0.0.0.0:4000/volgactf-quals-ctf-2015-my-little-pwnie/",
        "teaser":null},{
        "title": "ASIS CTF 2015 Quals -- grids",
        "excerpt":"Category: ProgrammingPoints: 300 In each stage send the maximun size of area that can be covered by given points as a vertex of polygon in 2D.nc 217.218.48.84 12433mirror 1 : nc 217.218.48.84 12432mirror 2 : nc 217.218.48.84 12434mirror 2 : nc 217.218.48.84 12429 Took me a while to figure out...","categories": ["write-ups"],
        "tags": ["ASIS","CTF","PPC","Python"],
        "url": "http://0.0.0.0:4000/asis-ctf-2015-quals/",
        "teaser":null},{
        "title": "DEFCON CTF 2015 Quals -- r0pbaby",
        "excerpt":"Category: Baby’s FirstPoints: 1 r0pbaby_542ee6516410709a1421141501f03760.quals.shallweplayaga.me:10436 64 bit ELF. No stack guard, but it has NX &amp; PIE protection.The service will give you a menu first: Welcome to an easy Return Oriented Programming challenge…Menu:1) Get libc address2) Get address of a libc function3) Nom nom r0p buffer to stack4) Exit Th...","categories": ["write-ups"],
        "tags": ["DEFCON","CTF","ROP","Pwnable","Python"],
        "url": "http://0.0.0.0:4000/defcon-ctf-2015-quals-r0pbaby/",
        "teaser":null},{
        "title": "DEFCON CTF 2015 Quals -- mathwhiz",
        "excerpt":"Category: Baby’s FirstPoints: 1 mathwhiz_c951d46fed68687ad93a84e702800b7a.quals.shallweplayaga.me:21249 The challenge’s pretty simple. The service will ask you a bunch of math problems(1000 actually), all you need to do is to answer all of them and you’ll get the flag. Notice that some of the questions contains some tricky input, like “ONE + TWO...","categories": ["write-ups"],
        "tags": ["Python","DEFCON","CTF","PPC"],
        "url": "http://0.0.0.0:4000/defcon-ctf-2015-quals-mathwhiz/",
        "teaser":null},{
        "title": "ASIS CTF 2015 Quals -- Saw this (1 & 2)",
        "excerpt":"Category: pwnPoints: 100 (Saw this-1), 400 (Saw this-2) Survive and get the flag!Note: This challenge contains two flags, one of them is easier to fetch, the other is harder. The easier flag will be clearly indicated as “Flag 1”, the harder flag as “Flag 2”nc 87.107.123.3 31337 64 bit ELF....","categories": ["write-ups"],
        "tags": ["ASIS","CTF","Pwnable","Python","format_string","C"],
        "url": "http://0.0.0.0:4000/asis-ctf-2015-quals-saw-this-1/",
        "teaser":null},{
        "title": "DEFCON CTF 2015 Quals -- catwestern",
        "excerpt":"Category: Coding ChallengePoints: 1 meowcatwestern_631d7907670909fc4df2defc13f2057c.quals.shallweplayaga.me 9999 Interesting challenge. First we connect to the service, it will send us the following message: ****Initial Register State****rax=0xfcf7659c7a4ad096rbx=0x1df0e8dfe8f70b53rcx=0x55004165472b9655rdx=0x1aa98e77006adf1rsi=0x949a482579724b11rdi=0x1e671d7b7ef9430r8=0x3251192496cee6a6r9=0x278d01e964b0efc8r10=0x1c5c8cca5112ad12r11=0x75a01cef4514d4f5r12=0xe109fd4392125cc7r13=0xe5e33405335ba0ffr14=0x633e16d0ec94137r15=0xb80a585e0cd42415****Send Solution In The Same Format****About to send 74 bytes: hŒråRI‡Ô�A]HÿÊI�Ç¢éNhIÿÊHÿÃ�HÎI�Ç^�…6H¤Ã M�ÃI÷ëH)ðH�ÆQØ8e�HÿÀIÁÕ�H5Œm'�Ã^CSo it seem like the service gave us the registers’ inital value, and a sequence of...","categories": ["write-ups"],
        "tags": ["Python","CTF","DEFCON","PPC","C","assembly"],
        "url": "http://0.0.0.0:4000/defcon-ctf-2015-quals-catwestern/",
        "teaser":null},{
        "title": "DEFCON CTF 2015 Quals -- wibbly-wobbly-timey-wimey",
        "excerpt":"Category: PwnablePoints: 2 Wibbly Wobbly Timey WimeyDon’t blink!wwtw_c3722e23150e1d5abbc1c248d99d718d.quals.shallweplayaga.me:2606 32 bit ELF, with Partial RELRO, stack canary found, NX &amp; PIE enabled.First we’ll have to play a game: You(^V&lt;&gt;) must find your way to the TARDIS(T) by avoiding the angels(A).Go through the exits(E) to get to the next room and continue...","categories": ["write-ups"],
        "tags": ["Python","C","DEFCON","CTF","Pwnable","format_string","PPC"],
        "url": "http://0.0.0.0:4000/defcon-ctf-2015-quals-wibbly-wobbly-timey-wimey/",
        "teaser":null},{
        "title": "AIS3 2015 pre-exam -- complete writeup",
        "excerpt":"考量到參與 AIS3 2015 pre-exam 的人幾乎都是台灣人這個 blog 的第一篇中文 writeup 就獻給這篇了 XD基本上就是全包這次 exam 的所有題目有問題歡迎留言討論 MISC MISC1 沒啥特別，範例 flag AIS3{hello_world} MISC2 給了一個 facebook.zip，有密碼老實說我最討厭這種需要解壓縮檔密碼的題目 = =每次打 CTF 遇到這類型題目沒有一次解出來過 = =也因此是我卡最久的一題 之後才知道說要用到一種攻擊叫做 known plaintext attack給定一個加密過的檔案，可以利用原檔案進行攻擊解密出 key網路上還有 tool 可以解，叫 pkcrack 因為壓縮檔裡面有張加密過的圖片所以可以根據檔名，想辦法 google 到原圖然後根據 pkcrack 官方網站裡面的 document 說明來進行解密基本上就是將原圖也壓成一個 zip 檔之後用 pkcrack 解出 key0, key1 和 key2最後用裡面附的 zipdecrypt...","categories": ["write-ups"],
        "tags": ["AIS3","CTF","Pwnable","Reversing","Crypto","Web","Python","C","PPC","format_string","Misc"],
        "url": "http://0.0.0.0:4000/ais3-2015-pre-exam-complete-writeup/",
        "teaser":null},{
        "title": "CSAW CTF 2015 -- Hacking Time",
        "excerpt":"Category: ReversingPoints: 200 This challenge gave us a NES ROM. After we launch it with NES debugger FCEUX, we found out that it eventually want us to input a password with 24 characters in length . We can found that our input was stored at memory address 0x05 ~ 0x1D....","categories": ["write-ups"],
        "tags": ["Python","CSAW","CTF","Z3","Reversing","NES"],
        "url": "http://0.0.0.0:4000/csaw-ctf-2015-hacking-time/",
        "teaser":null},{
        "title": "CSAW CTF 2015 -- FTP & FTP2",
        "excerpt":"Category: Reversing (FTP) &amp; Exploitable (FTP2)Points: 300 (FTP) &amp; 300 (FTP2) FTP 64 bit ELF. It’s a FTP-like service, we can list all the acceptable command by sending the HELP command. Here are some important commands that we’ll need to pass the challenges:USER [username]: enter username to loginPASS [password]: enter...","categories": ["write-ups"],
        "tags": ["Python","CTF","CSAW","Reversing","Pwnable","Z3"],
        "url": "http://0.0.0.0:4000/csaw-ctf-2015-ftp/",
        "teaser":null},{
        "title": "CSAW CTF 2015 -- wyvern",
        "excerpt":"Category: ReversingPoints: 500 Here they gave us another 64 bit ELF, which is apparently written in C++. It will ask us to input a secret, and tell us if we failed or success. The checking secret part in the program was really hard to understand what the actual f*ck is...","categories": ["write-ups"],
        "tags": ["ruby","CTF","CSAW","Reversing","pin","side-channel-attack"],
        "url": "http://0.0.0.0:4000/csaw-ctf-2015-wyvern/",
        "teaser":null},{
        "title": "CSAW CTF 2015 -- autobots",
        "excerpt":"Category: ExploitablePoints: 350 I hear bots are playing ctfs now.nc 52.20.10.244 8888 Once we connect to the service, it will send us a 64 bit ELF binary. int __cdecl main(int argc, const char **argv, const char **envp){ size_t v3; // rax@1 __int16 s; // [sp+0h] [bp-80h]@1 uint16_t v6; // [sp+2h]...","categories": ["write-ups"],
        "tags": ["Python","CSAW","CTF","PPC","Pwnable","ROP"],
        "url": "http://0.0.0.0:4000/csaw-ctf-2015-autobots/",
        "teaser":null},{
        "title": "Hack.lu CTF 2015 -- secret library",
        "excerpt":"Category: ReversingPoints: 200 64 bit ELF This service is a some kind of weird library system, which has the following functions: View the book title. You’ll have to be the “head librarian” ( = admin) first. View the book content (If you know the exact book title). Convert a binary...","categories": ["write-ups"],
        "tags": ["Hack.lu","Reversing","CTF","Python"],
        "url": "http://0.0.0.0:4000/hacklu-ctf-2015-secret-library/",
        "teaser":null},{
        "title": "MMA 2nd CTF 2016 -- greeting",
        "excerpt":"Category: pwnPoints: 150 After a long period of time without playing any CTF, I finally finished my master’s degree and have time to enjoy some CTF challenges. And then there is the Tokyo Western/MMA 2nd CTF, the first CTF I played in 2016. The challenge gave us a 32 bit...","categories": ["write-ups"],
        "tags": ["MMA","CTF","format_string","Python","Pwnable"],
        "url": "http://0.0.0.0:4000/mma-2nd-ctf-2016-greeting/",
        "teaser":null},{
        "title": "MMA 2nd CTF 2016 -- Interpreter",
        "excerpt":"Category: pwnPoints: 200 64 bit ELF, with FULL RELRO, NX, stack guard &amp; PIE enabled.After doing some reversing, we found that it’s a Befunge-93 program interpreter. It will first read some Befunge-93 instructions (at most 20000 characters), then interpret &amp; execute those instructions. The program will store those instructions at...","categories": ["write-ups"],
        "tags": ["Python","MMA","CTF","Pwnable"],
        "url": "http://0.0.0.0:4000/mma-2nd-ctf-2016-interpreter/",
        "teaser":null},{
        "title": "ASIS CTF Finals 2016 -- car market",
        "excerpt":"Category: pwnPoints: 177 64 bit ELF, with Partial RELRO, Canary &amp; NX enabled, no PIE. libc.so was provided. The binary is a car market program. It will let us list our cars’ info, add a car, remove a car and select a car. By selecting a car, we can edit...","categories": ["write-ups"],
        "tags": ["CTF","Pwnable","ASIS","Python","use_after_free","heap","off-by-one"],
        "url": "http://0.0.0.0:4000/asis-ctf-finals-2016-car-market/",
        "teaser":null},{
        "title": "ASIS CTF Finals 2016 -- shadow",
        "excerpt":"Category: pwnPoints: 99 32 bit ELF, with no NX, PIE, RELRO protection. The program will first use mmap to allocate a range of memory and treat it as a shadow stack, which stores the function return addresses.In the main function the program first ask us to input our name (the...","categories": ["write-ups"],
        "tags": ["CTF","ASIS","Python","Pwnable","shellcode","heap"],
        "url": "http://0.0.0.0:4000/869100/",
        "teaser":null},{
        "title": "HITCON CTF 2016 Quals -- Secret Holder",
        "excerpt":"Category: pwnPoints: 100 I did not finish the challenge during the contest, but was able to solve it after the game. Damn if only I can fuzz some more… 64 bit ELF, with Partial RELRO, canary &amp; NX enabled, no PIE.Program allow us to: keep secret : new a secret...","categories": ["write-ups"],
        "tags": ["Python","CTF","Pwnable","use_after_free","heap","HITCON","heap_overflow"],
        "url": "http://0.0.0.0:4000/hitcon-ctf-2016-quals-secret-holder/",
        "teaser":null},{
        "title": "HITCON CTF 2016 Quals -- flame",
        "excerpt":"Category: PPC ( more like Reverse )Points: 150 We were given a 32 bit PowerPC ELF.Fortunately I’ve got qemu-ppc-static installed on my ctf-box, so we can actually run the program by the following command: # root @ 9c51322c8256 in /mnt/files/hitcon-ctf-2016-qual/flame [7:51:02] $ qemu-ppc-static ./flame************************************** ** HITCON CTF 2016 Flag Verifier...","categories": ["write-ups"],
        "tags": ["ruby","CTF","HITCON","Reversing","PPC","PowerPC","assembly","qemu","C"],
        "url": "http://0.0.0.0:4000/hitcon-ctf-2016-quals-flame/",
        "teaser":null},{
        "title": "HITCON CTF 2016 Quals -- ROP",
        "excerpt":"Category: ReversePoints: 250 The challenge gave us a file call rop.iseq. By checking the file header, I found that it was a binary format of Ruby’s InstructionSequence. By googling the InstructionSequence, I found that there are some new features were added into the ruby version 2.3, for example the load_from_binary...","categories": ["write-ups"],
        "tags": ["CTF","HITCON","ruby","Reversing"],
        "url": "http://0.0.0.0:4000/hitcon-ctf-2016-quals-rop/",
        "teaser":null},{
        "title": "HITCON CTF 2016 Quals -- Hackpad",
        "excerpt":"Category: Crypto &amp; ForensicsPoints: 150 I did not look at this challenge at first, until I found that many teams have already solved this one except us, so I decide to give it a try :P It first gave us a pcap file. Several of my teammates have already extract...","categories": ["write-ups"],
        "tags": ["Python","CTF","HITCON","Crypto","Forensic","padding_oracle_attack"],
        "url": "http://0.0.0.0:4000/hitcon-ctf-2016-quals-hackpad/",
        "teaser":null},{
        "title": "HITCON CTF 2016 Quals -- Shelling Folder",
        "excerpt":"Category: pwnPoints: 200 64 bit ELF, with all the protection enabled. The program is a simple file system. You can create or delete files and folders, list files in a folder, change the current folder and calculate the size of a folder. It’s a unix-like file system, where folders are...","categories": ["write-ups"],
        "tags": ["CTF","HITCON","BOF","Pwnable","heap","Python"],
        "url": "http://0.0.0.0:4000/hitcon-ctf-2016-quals-shelling-folder/",
        "teaser":null},{
        "title": "SECCON CTF 2016 -- checker",
        "excerpt":"Category: ExploitPoints: 300 64 bit ELF with Full RELRO, stack canary, NX enabled, No PIE. A quick run of the program: $ ./checker Hello! What is your name?NAME : 123Do you know flag?&gt;&gt; 123Do you know flag?&gt;&gt; yesOh, Really??Please tell me the flag!FLAG : asdfYou are a liar...By reversing the...","categories": ["write-ups"],
        "tags": ["SECCON","CTF","BOF","Pwnable","Python"],
        "url": "http://0.0.0.0:4000/seccon-ctf-2016-checker/",
        "teaser":null},{
        "title": "SECCON CTF 2016 -- chat",
        "excerpt":"Category: ExploitPoints: 500 64 bit ELF with Partial RELRO, stack canary &amp; NX enabled, No PIE. The program is a simple tweet-chat service: $ ./chatSimple Chat Service1 : Sign Up 2 : Sign In0 : Exitmenu &gt; 1name &gt; userASuccess!1 : Sign Up 2 : Sign In0 : Exitmenu &gt;...","categories": ["write-ups"],
        "tags": ["SECCON","CTF","Pwnable","use_after_free","heap","heap_overflow","Python"],
        "url": "http://0.0.0.0:4000/seccon-ctf-2016-chat/",
        "teaser":null},{
        "title": "33C3 CTF 2016 -- pdfmaker",
        "excerpt":"Category: MiscPoints: 75 Just a tiny application, that lets the user write some files and compile them with pdflatex. What can possibly go wrong?nc 78.46.224.91 24242 So this is a service that allow us to create, show &amp; compile some files. create: Create a file. Valid file format are: .log,...","categories": ["write-ups"],
        "tags": ["33C3","CTF","Python","pdflatext","Misc"],
        "url": "http://0.0.0.0:4000/1255893/",
        "teaser":null},{
        "title": "33C3 CTF 2016 -- The 0x90s called",
        "excerpt":"Category: pwnPoints: 150 First we’ll have to go to a web page to start our challenge session. The page will show us the port (same IP address with the web page) and the ID/password. Once we connected to the remote host and login the machine, we’ll found that we’re inside...","categories": ["write-ups"],
        "tags": ["CTF","33C3","Pwnable","local_root"],
        "url": "http://0.0.0.0:4000/33c3-ctf-2016-the-0x90s-called/",
        "teaser":null},{
        "title": "33C3 CTF 2016 -- ESPR",
        "excerpt":"Category: pwnPoints: 150 This time there’s no binary or libc.so provided, only an image looks like this: eat: sleep:+-----------------+ +----------------+| sub rsp, 0x100 | | mov edi, 0x1 || mov rdi, rsp | | call _sleep || call _gets | | || | | |+-----------------+ +----------------+pwn: repeat:+-----------------+ +----------------+| mov rdi,...","categories": ["write-ups"],
        "tags": ["33C3","CTF","Python","Pwnable","format_string"],
        "url": "http://0.0.0.0:4000/33c3-ctf-2016-espr/",
        "teaser":null},{
        "title": "33C3 CTF 2016 -- babyfengshui",
        "excerpt":"Category: pwnPoints: 150 32 bit ELF, with Partial RELRO, canary &amp; NX enabled, No PIE program menu: $ ./babyfengshui0: Add a user1: Delete a user2: Display a user3: Update a user description4: ExitAdd a user: Action: 0size of description: 50 &lt;-- max length of descriptionname: AAAA text length: 12 &lt;--...","categories": ["write-ups"],
        "tags": ["33C3","CTF","Pwnable","heap_overflow","heap","Python"],
        "url": "http://0.0.0.0:4000/33c3-ctf-2016-babyfengshui/",
        "teaser":null},{
        "title": "33C3 CTF 2016 -- rec",
        "excerpt":"Category: pwnPoints: 200 32 bit ELF, with all the protection enabled. program menu: $ ./rec Calculators are fun!0 - Take note1 - Read note2 - Polish3 - Infix4 - Reverse Polish5 - Sign6 - Exit&gt; Take note: input a note Read note: output the note Polish: do the sum operation...","categories": ["write-ups"],
        "tags": ["33C3","CTF","Python","Pwnable"],
        "url": "http://0.0.0.0:4000/33c3-ctf-2016-rec/",
        "teaser":null},{
        "title": "DEFCON CTF 2017 Quals -- peROPdo",
        "excerpt":"Category: Potent Pwnables 32 bit ELF, static link, stripped, NX enabled, No PIE &amp; canary. The program is a “rolling dice” program. First we input our name, then the program will ask us how many dice would we like to roll. After we input a number, the program will start...","categories": ["write-ups"],
        "tags": ["Python","C","DEFCON","CTF","Pwnable","ROP","BOF","file_stream_pointer_overflow"],
        "url": "http://0.0.0.0:4000/1784510/",
        "teaser":null},{
        "title": "DEFCON CTF 2017 Quals -- badint",
        "excerpt":"Category: Potent Pwnables 64 bit ELF, Partial RELRO, NX enabled, No canary &amp; PIE. libc not provided. This C++ program will read some input from user, then store the data into the heap memory: $ ./badint SEQ #: 0Offset: 0Data: AAAAAAALSF Yes/No: YesRX PDU [0] [len=4]Assembled [seq: 0]: aaaaaa0aSEQ #:...","categories": ["write-ups"],
        "tags": ["Python","CTF","Pwnable","DEFCON","heap","heap_overflow","CPP"],
        "url": "http://0.0.0.0:4000/1784522/",
        "teaser":null},{
        "title": "Migrate to Github Pages",
        "excerpt":"So I finally decided to migrate my blog from Logdown to Github Pages. Took me about three days to get it done. Here I write down some notes to record the whole migration process. Installing Hexo I chose Hexo for my blog framework. Environment Setting First I prepared a docker...","categories": ["note"],
        "tags": ["Hexo","node.js","git","docker","NexT"],
        "url": "http://0.0.0.0:4000/Migrate-to-Github-Pages/",
        "teaser":null},{
        "title": "MeePwn CTF 2017 -- Old School",
        "excerpt":"Category: Pwnable 64 bit ELF, Partial RELRO, NX enabled, No PIE, has canary. -------- BookStore --------1. Add Book.2. Edit Book.3. Delete Book.4. Show Books.5. Exit.As we can see we can add, edit, delete or show a book. Books are stored in a pointer array books, each pointer point to a...","categories": ["write-ups"],
        "tags": ["CTF","Python","Pwnable","MeePwn","BOF"],
        "url": "http://0.0.0.0:4000/MeePwn-CTF-2017-Old-School/",
        "teaser":null},{
        "title": "MeePwn CTF 2017 -- anotherarena",
        "excerpt":"Category: Pwnable 64 bit ELF, Partial RELRO, canary &amp; NX enabled, No PIE. The program is a simple crackme program with multi-thread. First, the program will read the FLAG into a global buffer flag . Then, it will ask us to input the size of a buffer. Later the program...","categories": ["write-ups"],
        "tags": ["CTF","Pwnable","Python","MeePwn","heap"],
        "url": "http://0.0.0.0:4000/MeePwn-CTF-2017-anotherarena/",
        "teaser":null},{
        "title": "MeePwn CTF 2017 -- Brainfuck 1 & 2",
        "excerpt":"Category: Pwnable Both binaries are 64 bit ELF, No RELRO, No canary, PIE &amp; NX enabled. Brainfuck1 The program is a simple brainfuck language interpreter: it read input ( brainfuck code ), translate the code to the corresponding x86 machine code and execute it. For example, if we input +++++++++...","categories": ["write-ups"],
        "tags": ["CTF","Python","Pwnable","heap","MeePwn","brainfuck","shellcode"],
        "url": "http://0.0.0.0:4000/MeePwn-CTF-2017-Brainfuck-1-2/",
        "teaser":null},{
        "title": "hxp CTF 2017 -- hardened_flag_store",
        "excerpt":"Category: Pwnable 64 bit ELF with PIE, NX, FULL RELRO enabled The program will read a secret string from “secret.txt” and store the string address on stack. Then it will use seccomp to create a whitelist of syscalls. We can analyze the filter by using seccomp-tools: line CODE JT JF...","categories": ["write-ups"],
        "tags": ["CTF","Pwnable","Python","BOF","format_string","seccomp","hxp"],
        "url": "http://0.0.0.0:4000/hxp-CTF-2017-hardened-flag-store/",
        "teaser":null},{
        "title": "Learning browser exploitation via 33C3 CTF  feuerfuchs challenge",
        "excerpt":"Introduction So I’ve been playing with the browser exploitation recently, by studying some browser CTF challenges. So far I’ve tried qwn2own, SGX_Browser and feuerfuchs. qwn2own and SGX_Browser are both great for getting started with the brower exploitation. However, they are not “real world” enough, since both of them are small,...","categories": ["write-ups"],
        "tags": ["33C3","Firefox","Browser","SpiderMonkey","Javascript","CTF","Pwnable"],
        "url": "http://0.0.0.0:4000/Learning-browser-exploitation-via-33C3-CTF-feuerfuchs-challenge/",
        "teaser":null},{
        "title": "Chakrazy -- exploiting type confusion bug in ChakraCore engine",
        "excerpt":"Introduction Chakrazy is a browser CTF challenge created by team PPP for the 2017 PlaidCTF event. It’s a challenge based on Microsoft’s ChakraCore Javascript engine. You can download the challenge file here. Similar to my previous post, this post is more like a note about how I learn to exploit...","categories": ["write-ups"],
        "tags": ["CTF","Pwnable","Javascript","Plaid","Edge","ChakraCore","Browser","type_confusion"],
        "url": "http://0.0.0.0:4000/Chakrazy-exploiting-type-confusion-bug-in-ChakraCore/",
        "teaser":null}]
