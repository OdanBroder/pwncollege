# 1. Set a register:
> In this level you will work with registers! Please set the following:
>   rdi = 0x1337
```
section .text
        global _start
start:
mov rdi, 0x1337
```
# 2. Set multiple registers:
> In this level you will work with multiple registers. Please set the following:
>   rax = 0x1337
>   r12 = 0xCAFED00D1337BEEF
>   rsp = 0x31337
```
section .text
        global _start
start:
mov rax, 0x1337
mov r12, 0xCAFED00D1337BEEF
mov rsp, 0x31337
```
# 3. Addition:
> Do the following:
>   add 0x331337 to rdi
```
section .text
        global _start
start:
add rdi, 0x331337
```
# 4. Multiplication:
> Using your new knowledge, please compute the following:
>   f(x) = mx + b, where:
>     m = rdi
>     x = rsi
>     b = rdx
```
section .text
        global _start
start:
mov rax, rdi
imul rax, rsi
add rax, rdx
```
# 5. Division:
> Please compute the following:
>   speed = distance / time, where:
>     distance = rdi
>     time = rsi
>     speed = rax
-When you calculate `rax/register`, the result will save in rax and the remainder save in rdx.
```
section .text
        global _start
start:
mov rax, rdi
dil rax, rsi
```
# 6. Modulus:
> Please compute the following:
>   rdi % rsi
-The remainder will save in rdx.
```
section .text
        global _start
start:
mov rax, rdi
div rsi
xor rax, rax
mov rax, rdx
```
# 7. Register sizes:
> Another cool concept in x86 is the ability to independently access to lower register bytes.
> 
> Each register in x86_64 is 64 bits in size, and in the previous levels we have accessed
> the full register using rax, rdi or rsi.
> 
> We can also access the lower bytes of each register using different register names.
> 
> For example the lower 32 bits of rax can be accessed using eax, the lower 16 bits using ax,
> the lower 8 bits using al.
> 
> LSB                                      MSB
> +----------------------------------------+
> |                   rax                  |
> +--------------------+-------------------+
>                      |        eax        |
>                      +---------+---------+
>                                |   ax    |
>                                +----+----+
>                                | al | ah |
>                                +----+----+
> 
> Lower register bytes access is applicable to almost all registers.
> 
> Using only one move instruction, please set the upper 8 bits of the ax register to 0x42.
```
section .text
        global _start
start:
mov ah, 0x42
```
# 8. Register sizes for modulus:
> Using only the following instruction(s):
>   mov
> 
> Please compute the following:
>   rax = rdi % 256
>   rbx = rsi % 65536
```
section .text
        global _start
start:
mov rax, dil
mov rbx, si
```
# 9. Bitwise shift:
> Using only the following instructions:
>   mov, shr, shl
> 
> Please perform the following:
>   Set rax to the 5th least significant byte of rdi.
> 
> For example:
>   rdi = | B7 | B6 | B5 | B4 | B3 | B2 | B1 | B0 |
>   Set rax to the value of B4
```
section .text
        global _start
start:
shl rdi, 8
mov al, dil
```
# 10. Bitwise and:
> Without using the following instructions:
>   mov, xchg
> 
> Please perform the following:
>   rax = rdi AND rsi
> 
> i.e. Set rax to the value of (rdi AND rsi)
```
section .text
        global _start
start:
xor rax, rax
xor rax, rdi
and rax, rsi
```
# 11. Bitwise logic:
> Using only the following instructions:
>   and, or, xor
> 
> Implement the following logic:
>   if x is even then
>     y = 1
>   else
>     y = 0
> 
> where:
>   x = rdi
>   y = rax
```
section .text
        global _start
start:
xor rax, rax
or rax, 1
and rdi, 1
xor rax, rdi
```
# 12. Memory reads:
> Please perform the following:
>   Place the value stored at 0x404000 into rax
> 
> Make sure the value in rax is the original value stored at 0x404000.
```
section .text
        global _start
start:
mov rax, [0x404000]
```
# 13. Memory writes:
> Please perform the following:
>   Place the value stored in rax to 0x404000
```
section .text
        global _start
start:
mov [0x404000], rax
```
# 14. Memory reads and writes:
> Please perform the following:
>   Place the value stored at 0x404000 into rax
>   Increment the value stored at the address 0x404000 by 0x1337
> 
> Make sure the value in rax is the original value stored at 0x404000 and make sure
> that [0x404000] now has the incremented value.
```
section .text
        global _start
start:
mov rax, [0x404000]
mov rbx, 0x1337
add [0x404000], rbx
```
# 15. Read one size data:
> Please perform the following:
>   Set rax to the byte at 0x404000
```
section .text
        global _start
start:
mov al, [0x404000]
```
# 16. Read multiple data sizes:
> Please perform the following:
>   Set rax to the byte at 0x404000
>   Set rbx to the word at 0x404000
>   Set rcx to the double word at 0x404000
>   Set rdx to the quad word at 0x404000
```
section .text
        global _start
start:
mov al, [0x404000]
mov bx, [0x404000]
mov ecx, [0x404000]
mov rdx, [0x404000]
```
# 17. Dynamic address memory writes:
> Using the earlier mentioned info, perform the following:
>   Set [rdi] = 0xdeadbeef00001337
>   Set [rsi] = 0xc0ffee0000
```
section .text
        global _start
start:

mov rax, qword 0xdeadbeef00001337
mov rbx, 0xc0ffee0000
mov [rdi], rax
mov [rsi], rbx
```
# 18. Consecutive memory reads:
> Perform the following:
>   Load two consecutive quad words from the address stored in rdi
>   Calculate the sum of the previous steps quad words.
>   Store the sum at the address in rsi
```
section .text
        global _start
start:

xor rax, rax
add rax, [rdi]
add rax, [rdi + 8]
mov [rsi], rax
```
# 19. The stack:
> Using these instructions, take the top value of the stack, subtract rdi from it, then put it back.
```
section .text
        global _start
start:

pop rax
sub rax, rdi
push rax
```
# 20. Swap register values with the stack:
> Using only following instructions:
>   push, pop
> 
> Swap values in rdi and rsi.
> i.e.
> If to start rdi = 2 and rsi = 5
> Then to end rdi = 5 and rsi = 2
```
section .text
        global _start
start:

push rdi
pop rax
push rsi
pop rdi
push rax
pop rsi
```
# 21. Memory reads and writes with the stack:
> Without using pop, please calculate the average of 4 consecutive quad words stored on the stack.
> 
> Push the average on the stack.
```
section .text
        global _start
start:

mov rax, [rsp]
add rax, [rsp+  8]
add rax, [rsp + 16]
add rax, [rsp + 24]
mov rbx, 4
div rbx
push rax
```
# 22. Absolute jump:
> Jump to the absolute address 0x403000
```
section .text
        global _start
start:

mov rax, 0x403000
jmp rax 
```
# 23. Relative jump:
> Using the above knowledge, perform the following:
>   Make the first instruction in your code a jmp
>   Make that jmp a relative jump to 0x51 bytes from the current position
>   At the code location where the relative jump will redirect control flow set rax to 0x1
- You need to  use nop-sled.
```
.global _start
_start:
.intel_syntax noprefix

jmp next
.rept 0x51
nop
.endr
next:
mov rax, 0x1
```
# 24. Control flow:
```
Now, we will combine the two prior levels and perform the following:
  Create a two jump trampoline:
    Make the first instruction in your code a jmp
    Make that jmp a relative jump to 0x51 bytes from its current position
    At 0x51 write the following code:
      Place the top value on the stack into register rdi
      jmp to the absolute address 0x403000
```
```
.global _start
_start:
.intel_syntax noprefix


jmp next
.rept 0x51
nop
.endr
next:
pop rdi
mov rax, 0x403000
jmp rax
```
# 25. Conditional branches:
> Using the above knowledge, implement the following:
>   if [x] is 0x7f454c46:
>     y = [x+4] + [x+8] + [x+12]
>   else if [x] is 0x00005A4D:
>     y = [x+4] - [x+8] - [x+12]
>   else:
>     y = [x+4] * [x+8] * [x+12]
> 
> where:
>   x = rdi, y = rax.

-See condition in assembly at https://www.tutorialspoint.com/assembly_programming/assembly_conditions.htm.
```
section .text
        global _start
start:

mov eax, [rdi]
cmp eax, 0x7f454c46
je con1
cmp eax, 0x00005A4D
je con2
jmp con3
con1:
        mov eax, dword [rdi + 4]
        add eax, dword [rdi + 8]
        add eax, dword [rdi + 12]
        jmp end
con2:
        mov eax, dword [rdi + 4]
        sub eax, dword [rdi + 8]
        sub eax, dword [rdi + 12]
        jmp end
con3:
        mov eax, dword [rdi + 4]
        imul eax, dword [rdi + 8]
        imul eax, dword [rdi + 12]
        jmp end
end:
```
# 26. Jump tables:
> Using the above knowledge, implement the following logic:
>   if rdi is 0:
>     jmp 0x403016
>   else if rdi is 1:
>     jmp 0x4030eb
>   else if rdi is 2:
>     jmp 0x4031e2
>   else if rdi is 3:
>     jmp 0x403287
>   else:
>     jmp 0x403329
> 
> Please do the above with the following constraints:
>   Assume rdi will NOT be negative
>   Use no more than 1 cmp instruction
>   Use no more than 3 jumps (of any variant)
>   We will provide you with the number to 'switch' on in rdi.
>   We will provide you with a jump table base address in rsi.

-rdi register save value which is also index to jmp.
-rsi save the base address of starting jump.
```
section .text
        global _start
start:

cmp rdi, 3
jle okey
jmp [rsi + 32]
okey:
        jmp [rsi + rdi * 8]
```
# 27. Computing averages:
> Please compute the average of n consecutive quad words, where:
>   rdi = memory address of the 1st quad word
>   rsi = n (amount to loop for)
>   rax = average computed.

```
section .text
        global _start
start:

xor rbx, rbx
mov rax, [rdi]
jmp loop_computed
loop_computed:
        inc rbx
        add rax, [rdi + rbx * 8]
        cmp rbx, rsi
        jle loop_computed
        jmp end
end:
div rsi
```
# 28. Implementing strlen:
> Using the above knowledge, please perform the following:
>   Count the consecutive non-zero bytes in a contiguous region of memory, where:
>     rdi = memory address of the 1st byte
>     rax = number of consecutive non-zero bytes
> 
> Additionally, if rdi = 0, then set rax = 0 (we will check)!
> 
> An example test-case, let:
>   rdi = 0x1000
>   [0x1000] = 0x41
>   [0x1001] = 0x42
>   [0x1002] = 0x43
>   [0x1003] = 0x00
> 
> then: rax = 3 should be set
```

section .text
        global _start
_start:

xor rax, rax
cmp rdi, 0
jne loop
jmp end

loop:
        mov bl, [rdi]
        cmp bl, 0
        je end

        inc rax
        inc rdi

        jmp loop

end:
```
# 29. Using library functions:
> Please implement the following logic:
>   str_lower(src_addr):
>     i = 0
>     if src_addr != 0:
>       while [src_addr] != 0x00:
>         if [src_addr] <= 0x5a:
>           [src_addr] = foo([src_addr])
>           i += 1
>         src_addr += 1
>     return i 

1. The important point:
+ Foo takes a single argument as a value(rdi regisrer) and returns a value(rax register).
+ Foo is provided at 0x403000foo is provided at 0x403000.
+ Src_addr is an address in memory (where the string is located) and [src_addr] refers to the byte that exists at src_addr.
+ The function foo accepts **a byte** as its first argument and *returns* **a byte**.
+ Return value of rax register.
+ Ret with no argument pops the return address off of the stack and jumps to it. Some calling conventions (like __stdcall) specify that the callee function cleans up the stack.

2. Solution for this:
+ Save the value of rdi, rax register before calling function(you have to search topic **calling convention** for corresponding architecture; not only when calling foo function but also other funtion, the agrument are %rdi, %rsi, %rdx, %rcx, %r8 and %r9, respectively).

-This level will provide you the knowledge for calling convention, ret. Both of them are very important, you should look for topic about that problem because they are relative the bigger knowledge.
```
section .text
        global _start
_start:

xor rax, rax
xor rbx, rbx
cmp rdi, 0
je end
jmp str_lower
str_lower:
        ;Compare src_addr with 0
        cmp rdi, 0
        je end
        
        ;Compare [src_addr] with 0
        mov bl, [rdi]
        cmp rbx, 0
        je end
        
        ;Compare [src_addr] with 0x5a
        cmp rbx, 0x5a
        jg next                             ;jump if greater

        push rdi                            ;save the value of rdi
        push rax                            ;save the value of rdi
        xor rdi, rdi                        ;make that rdi is 0
        mov dil, bl                         ;take first agrument(a byte)
        mov rcx, 0x403000 
        call rcx                            ;call function

        mov bl, al                          ;take result after call function to bl(rbx)
        pop rax                             ;restore rax
        pop rdi                             ;restore rdi
        mov [rdi], bl                       ;take result

        inc rax
        jmp next

next:
        inc rdi
        jmp str_lower

end:
        ret
```
# 30. Compute the most common byte:
> Once, again, please make function(s) that implements the following:
> most_common_byte(src_addr, size):
>   i = 0
>   while i <= size-1:
>     curr_byte = [src_addr + i]
>     [stack_base - curr_byte] += 1
>     i += 1
> 
>   b = 0
>   max_freq = 0
>   max_freq_byte = 0
>   while b <= 0xff:
>     if [stack_base - b] > max_freq:
>       max_freq = [stack_base - b]
>       max_freq_byte = b
>     b += 1
> 
>   return max_freq_byte

-In level 29, we know what does `ret` work. And now, we will study about `stack frame`, it is essential to solve this challenge.


-I don't know exactly why without this, my program will crash, I have search and see that explain in: https://www.freebuf.com/articles/database/321326.html
```
section .text
        global _start
start:

push 0                             
mov rbp, rsp
sub rsp, rsi                            ;the size is the value in rsi
xor rax, rax
xor rbx, rbx
sub si, 1                               ;size - 1
jmp loop1

loop1:
        cmp rax, rsi                    ;i
        jg next

        xor rbx, rbx
        mov bl, [rdi + rax]
        mov r11, rbp
        sub r11, rbx
        inc byte [r11]

        inc rax
        jmp loop1
next:
        xor rbx, rbx                    ;b
        xor rcx, rcx                    ;max_freq
        xor rax, rax                    ;max_freq_byte
        jmp loop2
loop2:
        cmp bx, 0xff
        jg end

        xor rdi, rdi
        mov r9, rbp
        sub r9, rbx
        mov dl, [r9]
        cmp dl, cl
        jg find

        inc bx
        jmp loop2
find:
        mov cl, dl
        mov al, bl
        jmp loop2

end:
        mov rsp, rbp
        pop rbx
        ret
```
