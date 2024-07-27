#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('/challenge/babyrev_level12.0', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc 

gs = """
b *main
b *execute_program
b *execute_program+61
b *execute_program185
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

io = start()
io.sendafter(b'[+]\n', b'6\xfcs\xafw\x14')
io.interactive()
