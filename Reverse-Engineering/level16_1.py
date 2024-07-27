#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('/challenge/babyrev_level16.1', checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc 

gs = """
b *0x55555555691b
b *0x555555555d99
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

def ans():
    global a1_arr
    res = ""
    for i in range(147, 155):
        res += f"{a1_arr[i]:02x}" 
    print(res)
    
    return bytes.fromhex(res)

io = start()
io.sendafter(b'[+] registers, memory, and system calls.\n', b'\x83]\xa8\xd1')
io.interactive()
