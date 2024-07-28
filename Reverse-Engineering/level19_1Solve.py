#!/usr/bin/env python3
from pwn import *

#context.log_level = 'debug'
context.binary = elf = ELF('/challenge/babyrev_level19.1', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc 

gs = """
b *main
"""

def info(mess):
    return log.info(mess)

def success(mess):
    return log.success(mess)

def error(mess):
    log.error(mess)


def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})


payload = b'\xcf' + b'\x03' + b'\x5a' + b'\xba' + b'\x3a' + b'\x75' +b'\x40' + b'\x91' + b'\x3a' + b'\x4e' + b'\xcc' + b'\x27'
print(len(payload))
io = start()
io.sendafter(b'KEY: ', payload)
io.interactive()
