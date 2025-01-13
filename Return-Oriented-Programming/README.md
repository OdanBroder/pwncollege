# Babyrop_level1

## Level 1.0

![image](img/level1/1_1_question.png)

- It gives me full information; however, I will debug it to be legit=)).

![image](img/level1/1_2_challenge.png)

- ![image](img/level1/1_3_challenge.png)
- offset: 152
- address of win: 0x401fca

***I will add ret gadget to avoid the stack alignment.***

![image](img/level1/1_4.png)

- ![image](img/level1/1_5.png)

### Payload
[solve.py](code/10.py)

## Level 1.1

![image](img/level1/1_6.png)

It doesn't show me anything; however, my work is totally similar to level 1.0.

#### Payload 
[solve.py](code/11.py)

# Babyrop_level2

## The useful knowledge

[lseek](https://www.tutorialspoint.com/unix_system_calls/lseek.htm)

[man lseek](https://www.man7.org/linux/man-pages/man2/lseek.2.html)


![image](img/level2/2_1.png)


## Level 2.0

![image](img/level2/2_2.png)

**It gives me full information; however, I will debug it to be legit=)).**

![image](img/level2/2_3.png)

- ![image](img/level2/2_4.png)


![image](img/level2/2_5.png)

![image](img/level2/2_6.png)

**I will check win_stage_1 and win_stage_2**

![image](img/level2/2_7.png)

![image](img/level2/2_8.png)

Hmmmm, it is so complicated and unclear. Therefore, I will download the file challenge and use IDA to check it clearly.

![image](img/level2/2_9.png)

- First, the function will open file "/flag" and move the pointer to the end of the file; afterward, it will divide by 2 and add 1, which also means moving the pointer to the middle of the file, and getting the size from the beginning file to middle to the v3. In conclusion, it is easy to understand that 
    - `v3 = strlen("content in fileflag")/2 `
    - I will call the length in "/flag": len
- Then, it move the pointer to the beginning of file "/flag"
- Afterward, It read `len / 2` from the beginning of the file to buf
- Finally, it will write buf to stdout.
- **So, I only have the half of flag**

![image](img/level2/2_10.png)

- First, the function will open file "/flag" and move the pointer to the end of the file; afterward, it will divide by 2 and add 1, which also means moving the pointer to the middle of the file, and getting the size from the beginning file to middle to the v3. In conclusion, it is easy to understand that 
    - `v3 = strlen("content in fileflag")/2 `
    - I will call the length in "/flag": len
- Then, it move the pointer to the middle of file "/flag"
- Afterward, It read `len / 2` from the beginning of the file to buf
- Finally, it will write buf to stdout.
- **So, I only have the end half of flag**

**I must call both win_stage_1 and win_stage_2 to have full flag**

### Payload 
[solve.py](code/20.py)


## Level 2.1

![image](img/level2/2_11.png)


It doesn't show me anything; however, my work is totally similar to level 2.0.


[solve.py](code/21.py)

# Babyrop_level3

## The useful knowledge

[Calling convention](https://stackoverflow.com/questions/2535989/what-are-the-calling-conventions-for-unix-linux-system-calls-and-user-space-f)

## Level 3.0

![image](img/level3/30.png)

**It gives me full information; however, I will debug it to be legit=)).**

![image](img/level3/31.png)

![image](img/level3/32.png)

- ![image](img/level3/33.png)

![image](img/level3/34.png)

- ![image](img/level3/35.png)

![image](img/level3/36.png)

- ![image](img/level3/37.png)

![image](img/level3/38.png)

- ![image](img/level3/39.png)

![image](img/level3/40.png)

- ![image](img/level3/41.png)

**Each win_stage_* divides my content into the file "/flag", so I must call both of them to get the flag*

**However, I need to pass agrument to each function. Acccording to the calling convention**

```
The kernel interface uses %rdi, %rsi, %rdx, %r10, %r8 and %r9.
```
**, I need pass the agrument to rdi**

Find the information

![image](img/level3/42.png)

- `offset: 104`

![image](img/level3/43.png)

- ![image](img/level3/44.png)

![image](img/level3/45.png)

- ![image](img/level3/46.png)


### Payload 
[solve.py](code/30.py)

## Level 3.1

![image](img/level3/47.png)

It doesn't show me anything; however, my work is totally similar to level 3.0.

### Payload 
[solve.py](code/31.py)


# Babyrop_level4

## Level 4.0

![image](img/level4/00.png)

- It gives me the information about the address of my input in stack

![image](img/level4/01.png)

- ![image](img/level4/02.png)

I don't see the useful information to get the flag; so, I need to check the gadget

![image](img/level4/03.png)

![image](img/level4/04.png)

![image](img/level4/05.png)

![image](img/level4/06.png)

*No function can be used for getting the flag, so I must find the gadget or something to do it.*

![image](img/level4/06.png)

![image](img/level4/07.png)

![image](img/level4/08.png)

![image](img/level4/09.png)

![image](img/level4/10.png)

***I will pass the string "/flag" somewhere in the stack, where I know the address of it, to make the pointer for the agrument when I use syscall***

- Such as the address start from my input

### The ~~trick~~ approach
**Hmm, i think about the syscall, such as open, read and write the flag**


***However, I can't find the useful gadget to get the file descriptor from register rax ro rdi for my read syscall***

![image](img/level4/11.png)

![image](img/level4/12.png)

![image](img/level4/13.png)



**Thus, I find many ways to do read syscall, but it doesn't work.**

[man open(2)](https://www.man7.org/linux/man-pages/man2/open.2.html#RETURN_VALUE)

![image](img/level4/14.png)

**So, I try to pass file descriptor is 3. Luckily, it is successful.**

### Payload 1

[solve.py](code/40_trick.py)

### Payload 2

***I will use chmod syscall; afterward, I will cat "/flag"***

[man chmod(1)](https://www.man7.org/linux/man-pages/man1/chmod.1.html)

![image](img/level4/15.png)


[solve.py](code/40.py)

## Level 4.1

It doesn't show me anything; however, my work is totally similar to level 4.0.

### Payload 1

***open, read, write syscall***

[solve.py](code/41_orw.py)

### Payload 2

***chmod syscall***

[solve.py](code/41_chmod.py.py)

# Babyrop_level5

## Level 5.0

***Let's check the gadget***

![image](img/level5/00.png)

![image](img/level5/01.png)

![image](img/level5/02.png)

![image](img/level5/03.png)

![image](img/level5/04.png)

- ![image](img/level5/05.png)
- ![image](img/level5/06.png)
- ![image](img/level5/07.png)
- ![image](img/level5/08.png)
- ![image](img/level5/09.png)

### The uncompleted approach

![image](img/level5/10.png)

As you see, ***there are no stack leaks and ASLR is enable***

![image](img/level5/11.png)

However, I see the useful gadget to pass my input to the address.

I don't know the address of stack, so I try to check the other region.

![image](img/level5/12.png)

`.data: 0x0000000000404078`

![image](img/level5/13.png)


**In debug**

- ![image](img/level5/14.png)

*So, I pick the address 0x4040ff for my "/flag" and open, read, and write a system call like in the previous challenge.*

[solve_fail.py](code/50_test.py)

One of the ouputs I receive

![image](img/level5/15.png)

I don't know why it contains those instructions; therefore, I try to go with the bigger offset `0x4041ff`.

![image](img/level5/16.png)

It still doesn't work

I have tried and tried to find other writeable space, but there is no hope!!!

~~I was stuck and panic.~~

### The approach 

After many attempts to think about this challenge, I have succeeded.

***I will use libc to do my work. I think about using system() to get the shell with root permission.***

The interesting is that ***root permission***

How can do it???

I see **setuid**

![image](img/level5/17.png)

![image](img/level5/18.png)

I find some informations about this, and take the reuslt.

[setuid(0) fails to execute for root owned program](https://stackoverflow.com/questions/28395862/setuid0-fails-to-execute-for-root-owned-program)

![image](img/level5/19.png)

- It will be successful if the program has this 

![image](img/level5/20.png)

Okeyyyyy, it is possible to do it.

#### ***How do I find the address?***
- I will leak the address of puts() relying on puts_plt and puts_got.

Next, we will find the address of string "/bin/sh", system(), setuid() depend the offset between them and the address of puts, and use them.

![image](img/level5/21.png)

So, I will find the information in `/lib/x86_64-linux-gnu/libc.so.6`

![image](img/level5/22.png)

- `puts_got: 0x404028`

![image](img/level5/23.png)

- `puts_plt : 0x401110`


```python
from pwn import *



context.log_level = 'debug'
offset = b'a'*88

puts_plt = p64(0x401110)
puts_got = p64(0x404028)


ret = p64(0x40101a)
poprax_ret          = p64(0x401c28)
poprdi_ret          = p64(0x401c60)
poprsi_ret          = p64(0x401c58)
poprdx_ret          = p64(0x401c38)
syscall = p64(0x401c30)

payload_leak = offset
payload_leak += poprdi_ret
payload_leak += puts_got
payload_leak += puts_plt

r = process('/challenge/babyrop_level5.0')
r.recvuntil(b'Return Oriented Programming!\n')
r.sendline(payload_leak)


r.interactive()
```

![image](img/level5/24.png)

Okey, it leaks for me the address of puts; I will take it as the hex value


```python
def bytes_to_hex(data):
  """Converts bytes to a hex  and reverses the byte order.

  Args:
    data: A byte string.

  Returns:
    A hex  with the byte order reversed.
  """
  return int(''.join(['{:02x}'.format(b) for b in reversed(data)]), 16)
```

```python
from pwn import *


def bytes_to_hex(data):
  """Converts bytes to a hex  and reverses the byte order.

  Args:
    data: A byte string.

  Returns:
    A hex  with the byte order reversed.
  """
  return int(''.join(['{:02x}'.format(b) for b in reversed(data)]), 16)

context.log_level = 'debug'
offset = b'a'*88

puts_plt = p64(0x401110)
puts_got = p64(0x404028)


ret = p64(0x40101a)
poprax_ret          = p64(0x401c28)
poprdi_ret          = p64(0x401c60)
poprsi_ret          = p64(0x401c58)
poprdx_ret          = p64(0x401c38)
syscall = p64(0x401c30)

payload_leak = offset
payload_leak += poprdi_ret
payload_leak += puts_got
payload_leak += puts_plt

r = process('/challenge/babyrop_level5.0')
r.recvuntil(b'Return Oriented Programming!\n')
r.sendline(payload_leak)
r.recvuntil(b'Leaving!\n')
addr_puts_byte = r.recv(6)
addr_puts = bytes_to_hex(addr_puts_byte)
print(f"LEAKKKKKKKKKK {addr_puts_byte} : {hex(addr_puts)}")


r.interactive()
```

![image](img/level5/25.png)

#### Hmmm, however, I only have one input

What happens if I call the main again?

This idea sound good.

![image](img/level5/26.png)

```python
payload_leak = offset
payload_leak += poprdi_ret
payload_leak += puts_got
payload_leak += puts_plt
payload_leak += main     #0x401d88

r = process('/challenge/babyrop_level5.0')
r.recvuntil(b'Return Oriented Programming!\n')
r.sendline(payload_leak)
r.recvuntil(b'Leaving!\n')
addr_puts_byte = r.recv(6)
addr_puts = bytes_to_hex(addr_puts_byte)
print(f"LEAKKKKKKKKKK {addr_puts_byte} : {hex(addr_puts)}")

r.recvuntil(b'Return Oriented Programming!\n')
r.sendline(b'a'*10)


r.interactive()
```

![image](img/level5/27.png)

***It seems that I call the main again unsuccessful.***


I have spent many time for this, and have the result.

I use IDA to see this, `View -> Graphs -> Function calls`

![image](img/level5/28.png)


***I try with _start and it works.***

![image](img/level5/29.png)

![image](img/level5/30.png)


#### Okey, I will find the offset between puts and others


![image](img/level5/31.png)

- `offset of puts in libc: 0x84420`

![image](img/level5/32.png)

- `offset of system in libc: 0x52290`

![image](img/level5/33.png)

- `offset of "/bin/sh" in libc: 0x1b45bd`

![image](img/level5/34.png)

- `offset of setuid in libc: 0xe4150`

***The step***
- Leak the address of puts() relying on puts_plt and puts_got.
- Rewind the main.
- Find the address of string "/bin/sh", system(), setuid() depend the offset between them and the address of puts.
- Call them

### Payload 

[solve.py](code/50.py)

## Level 5.1

It is totally similar to level 5.0; however, to make it simple, I will use the power of pwntools to write my script.

### Payload

[solve.py](code/51.py)

# Babyrop_level6

It is totally similar to level 5; however, to make it simple, I will use the power of pwntools to write my script.

## Level 6.0

### Payload

[solve.py](code/60.py)

## Level 6.1

[solve.py](code/61.py)

# Babyrop_level7 && Babyrop_level 8

**They are the same as the previous challenge =)))))**

# Babyrop_level9

## Level 9.0

It is a special challenge, I need to use stack pivot to solve this.

![image](img/level9/00.png)

![image](img/level9/01.png)

- As you see, it take input into `0x4140e0 <data+65536>`, this address is not in the stack. However, it will copy 0x18(24) bytes from this address into rbp+8(this save return address)
- It means I only have 3 gadgets to run my ROPchain.

![image](img/level9/02.png)

![image](img/level9/03.png)

![image](img/level9/04.png)

- The useful gadget to make stack pivot.
    - ![image](img/level9/05.png)
    - ![image](img/level9/06.png)
    - [Assembly x86 - "leave" Instruction](https://stackoverflow.com/questions/29790175/assembly-x86-leave-instruction) 

> leave is exactly equivalent to
> 
> mov   %rbp, %rsp     # rsp = rbp,  mov  rsp,rbp in Intel syntax
> 
> pop   %rbp  

- So, I will contol rsp to the address store my gadget.

### Payload

[solve.py](code/90.py)

## Level 9.1

### Payload

[solve.py](code/91.py)

# Babyrop_level10

## Level 10.0

![images](img/level10/00.png)

- As you see, the challenge require call win function to get the flag. However, win function has just been dynamically(random) constructed on the stack.
- If I only get this address of win function and ret, I will not study more=))).
- Thus, I will use the approach to solve this challenge which only use the information about leaking stack.
- I download this chall and library into my computer to use pwndbg, it is convenient to do this than gdb=)).

![images](img/level10/01.png)

![images](img/level10/02.png)

![images](img/level10/03.png)

***This is win function.***

![images](img/level10/04.png)

- However, **PIE enable**,hm......
- I can't find the address of gadget to use it.
- Notably
    - ![images](img/level10/05.png)
        - This is the image before I start the program.    
    - ![images](img/level10/06.png)
        - - This is the image after I start the program. 

- As you see, PIE is not random all byte.
- Therefore, I can overwrite the least significant(with 0x2f) byte to use gadget 
    - ![images](img/level10/07.png)
    - It will control rsp as the previous challenge I solved.


### Payload 

[solve.py](code/100.py)

## Level 10.1

### Payload 

[solve.py](code/101.py)

# Babyrop_level11

## Level 11.0

![image](img/level11/00.png)

- Hmmm, I use the technique stack pivot in this challenge. In this challenge, I will do it similar to the previous challenge; however, the ***PIE will not change in 1.5 bytes =))) (i debug to see this)***. Therefore, I need to do this several times to get the flag. 

![image](img/level11/01.png)

![image](img/level11/02.png)

### Payload

[solve.py](code/110.py)

## Level 11.1

### Payload

[solve.py](code/111.py)

# Babyrop_level12

## Level 12.0

![image](img/level12/00.png)

**In this challenge, I also download this challenge and the libc of this challenge. I spent many times to think to solve this challenge without brute-force =)))).**

First, we need to know challenge work.
- This challenge doesn't have challenge() function, and it does anything in main() function before return to ***_libc_start_call_main+128*** it also means I can't use `leave ; ret` gadget in the challenge 
    - ![image](img/level12/01.png)
    - ![image](img/level12/02.png)

Yepp, I also need to find gadget "leave ; ret" to use technique stack pivot. Because the program return to libc, so I need to find it in libc.

![image](img/level12/03.png)

- ![image](img/level12/04.png)
- ![image](img/level12/05.png)
- ![image](img/level12/06.png)

As you see, I need to brute-force more nibble than in the previous challenge. Thus, I see it is not legitable to do this method, I find other ways to resolve challenge. 

Until I'm stuck and panic because of spending many times. Finnaly, I brute-force and wait to get the flag. Because the libc in the sever of pwncollege is not the same as my local. So, I will find the offset of gadget in sever. 

![image](img/level12/07.png)

![image](img/level12/08.png)

### Payload

[solve.py](code/120.py)

## Level 12.1

### Payload

[solve.py](code/121.py)

