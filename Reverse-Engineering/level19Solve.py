#!/usr/bin/env python3
from pwn import *

#context.log_level = 'debug'
context.binary = elf = ELF('/challenge/babyrev_level19.0', checksec=False)

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


payload = b';' + b'8' + b'g' + b'X' + b'\x09' + b'\x90' +b'B' + b'\xeb' + b'\xc3' + b'g' + b'\xbb' + b'E'
io = start()
io.sendafter(b'[s] ... read_memory\n', payload)
io.interactive()
