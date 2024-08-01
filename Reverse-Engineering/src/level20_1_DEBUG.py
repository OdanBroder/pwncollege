#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"
context.binary = elf = ELF("./babyrev_level20.1", checksec=False)

libc = elf.libc

gs = """
b *0x555555555bf6
b *0x555555555b73
b *0x555555555a72
"""

info = lambda msg: log.info(msg)
success = lambda msg: log.success(msg)
error = lambda msg: log.error(msg)
sla = lambda msg, data: io.sendlineafter(msg, data)
sa = lambda msg, data: io.sendafter(msg, data)
sl = lambda data: io.sendline(data)
s = lambda data: io.send(data)


def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path}, gdbscript=gs)
    elif args.REMOTE:
        return remote(
            "",
        )
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})


dest = 0x7fffffffdaf0
a1 = dest
dest_sub_0x20 = dest - 0x20
vm_mem = 0x5555555592e0
vm_mem_sub_0x280 = vm_mem - 0x280
vm_code = 0x555555559020
vm_code_length = 0x2a3


a1_arr = [0] * 1024
a1_1024 = [0] * 10
aAbcdsif = 0x555555557024


"""
0x555555557024: 0x61
0x555555557026: 0x62
0x555555557028: 0x63
0x55555555702a: 0x64
0x55555555702c: 0x73
0x55555555702e: 0x69
0x555555557030: 0x66
0x555555557032: 0x4e
"""
flag_description = 0x555555559300
flag_description_arr = [None] * 8

dic_dest = {
    dest_sub_0x20+0x020 : int("0x08", 16) ,                  
    dest_sub_0x20+0x021 : int("0x20", 16) , 
    dest_sub_0x20+0x022 : int("0x02", 16) , 
    dest_sub_0x20+0x023 : int("0x04", 16) , 
    dest_sub_0x20+0x024 : int("0x02", 16) , 
    dest_sub_0x20+0x025 : int("0x08", 16) , 
    dest_sub_0x20+0x026 : int("0x02", 16) , 
    dest_sub_0x20+0x027 : int("0x20", 16) , 
    dest_sub_0x20+0x028 : int("0xC1", 16) , 
    dest_sub_0x20+0x029 : int("0x10", 16) , 
    dest_sub_0x20+0x02A : int("0x20", 16) , 
    dest_sub_0x20+0x02B : int("0x05", 16) , 
    dest_sub_0x20+0x02C : int("0x20", 16) , 
    dest_sub_0x20+0x02D : int("0x20", 16) , 
    dest_sub_0x20+0x02E : int("0x01", 16) , 
    dest_sub_0x20+0x02F : int("0x10", 16) , 
    dest_sub_0x20+0x030 : int("0x08", 16) , 
    dest_sub_0x20+0x031 : int("0x08", 16) , 
    dest_sub_0x20+0x032 : int("0x00", 16) , 
    dest_sub_0x20+0x033 : int("0x02", 16) , 
    dest_sub_0x20+0x034 : int("0x20", 16) , 
    dest_sub_0x20+0x035 : int("0x00", 16) , 
    dest_sub_0x20+0x036 : int("0x02", 16) , 
    dest_sub_0x20+0x037 : int("0x02", 16) , 
    dest_sub_0x20+0x038 : int("0x00", 16) , 
    dest_sub_0x20+0x039 : int("0x02", 16) , 
    dest_sub_0x20+0x03A : int("0x10", 16) , 
    dest_sub_0x20+0x03B : int("0x02", 16) , 
    dest_sub_0x20+0x03C : int("0x20", 16) , 
    dest_sub_0x20+0x03D : int("0x30", 16) , 
    dest_sub_0x20+0x03E : int("0x10", 16) , 
    dest_sub_0x20+0x03F : int("0x20", 16) , 
    dest_sub_0x20+0x040 : int("0x1B", 16) , 
    dest_sub_0x20+0x041 : int("0x20", 16) , 
    dest_sub_0x20+0x042 : int("0x20", 16) , 
    dest_sub_0x20+0x043 : int("0x00", 16) , 
    dest_sub_0x20+0x044 : int("0x02", 16) , 
    dest_sub_0x20+0x045 : int("0x08", 16) , 
    dest_sub_0x20+0x046 : int("0x08", 16) , 
    dest_sub_0x20+0x047 : int("0x10", 16) , 
    dest_sub_0x20+0x048 : int("0x02", 16) , 
    dest_sub_0x20+0x049 : int("0x00", 16) , 
    dest_sub_0x20+0x04A : int("0x02", 16) , 
    dest_sub_0x20+0x04B : int("0x02", 16) , 
    dest_sub_0x20+0x04C : int("0x00", 16) , 
    dest_sub_0x20+0x04D : int("0x20", 16) , 
    dest_sub_0x20+0x04E : int("0x02", 16) , 
    dest_sub_0x20+0x04F : int("0x00", 16) , 
    dest_sub_0x20+0x050 : int("0x04", 16) , 
    dest_sub_0x20+0x051 : int("0x20", 16) , 
    dest_sub_0x20+0x052 : int("0x2D", 16) , 
    dest_sub_0x20+0x053 : int("0x20", 16) , 
    dest_sub_0x20+0x054 : int("0x80", 16) , 
    dest_sub_0x20+0x055 : int("0x10", 16) , 
    dest_sub_0x20+0x056 : int("0x02", 16) , 
    dest_sub_0x20+0x057 : int("0x80", 16) , 
    dest_sub_0x20+0x058 : int("0x10", 16) , 
    dest_sub_0x20+0x059 : int("0x08", 16) , 
    dest_sub_0x20+0x05A : int("0x20", 16) , 
    dest_sub_0x20+0x05B : int("0xFF", 16) , 
    dest_sub_0x20+0x05C : int("0x20", 16) , 
    dest_sub_0x20+0x05D : int("0x80", 16) , 
    dest_sub_0x20+0x05E : int("0x08", 16) , 
    dest_sub_0x20+0x05F : int("0x02", 16) , 
    dest_sub_0x20+0x060 : int("0x80", 16) , 
    dest_sub_0x20+0x061 : int("0x08", 16) , 
    dest_sub_0x20+0x062 : int("0x00", 16) , 
    dest_sub_0x20+0x063 : int("0x02", 16) , 
    dest_sub_0x20+0x064 : int("0x20", 16) , 
    dest_sub_0x20+0x065 : int("0x00", 16) , 
    dest_sub_0x20+0x066 : int("0x02", 16) , 
    dest_sub_0x20+0x067 : int("0x02", 16) , 
    dest_sub_0x20+0x068 : int("0x20", 16) , 
    dest_sub_0x20+0x069 : int("0x01", 16) , 
    dest_sub_0x20+0x06A : int("0x20", 16) , 
    dest_sub_0x20+0x06B : int("0x02", 16) , 
    dest_sub_0x20+0x06C : int("0x01", 16) , 
    dest_sub_0x20+0x06D : int("0x02", 16) , 
    dest_sub_0x20+0x06E : int("0x20", 16) , 
    dest_sub_0x20+0x06F : int("0x04", 16) , 
    dest_sub_0x20+0x070 : int("0x02", 16) , 
    dest_sub_0x20+0x071 : int("0x02", 16) , 
    dest_sub_0x20+0x072 : int("0x02", 16) , 
    dest_sub_0x20+0x073 : int("0x00", 16) , 
    dest_sub_0x20+0x074 : int("0x20", 16) , 
    dest_sub_0x20+0x075 : int("0x02", 16) , 
    dest_sub_0x20+0x076 : int("0x00", 16) , 
    dest_sub_0x20+0x077 : int("0x08", 16) , 
    dest_sub_0x20+0x078 : int("0x20", 16) , 
    dest_sub_0x20+0x079 : int("0x25", 16) , 
    dest_sub_0x20+0x07A : int("0x04", 16) , 
    dest_sub_0x20+0x07B : int("0x10", 16) , 
    dest_sub_0x20+0x07C : int("0x08", 16) , 
    dest_sub_0x20+0x07D : int("0x08", 16) , 
    dest_sub_0x20+0x07E : int("0x20", 16) , 
    dest_sub_0x20+0x07F : int("0xFF", 16) , 
    dest_sub_0x20+0x080 : int("0x10", 16) , 
    dest_sub_0x20+0x081 : int("0x80", 16) , 
    dest_sub_0x20+0x082 : int("0x08", 16) , 
    dest_sub_0x20+0x083 : int("0x08", 16) , 
    dest_sub_0x20+0x084 : int("0x20", 16) , 
    dest_sub_0x20+0x085 : int("0x00", 16) , 
    dest_sub_0x20+0x086 : int("0x10", 16) , 
    dest_sub_0x20+0x087 : int("0x04", 16) , 
    dest_sub_0x20+0x088 : int("0x08", 16) , 
    dest_sub_0x20+0x089 : int("0x08", 16) , 
    dest_sub_0x20+0x08A : int("0x20", 16) , 
    dest_sub_0x20+0x08B : int("0x13", 16) , 
    dest_sub_0x20+0x08C : int("0x04", 16) , 
    dest_sub_0x20+0x08D : int("0x10", 16) , 
    dest_sub_0x20+0x08E : int("0x08", 16) , 
    dest_sub_0x20+0x08F : int("0x08", 16) , 
    dest_sub_0x20+0x090 : int("0x02", 16) , 
    dest_sub_0x20+0x091 : int("0x10", 16) , 
    dest_sub_0x20+0x092 : int("0x04", 16) , 
    dest_sub_0x20+0x093 : int("0x02", 16) , 
    dest_sub_0x20+0x094 : int("0x00", 16) , 
    dest_sub_0x20+0x095 : int("0x02", 16) , 
    dest_sub_0x20+0x096 : int("0x20", 16) , 
    dest_sub_0x20+0x097 : int("0xB7", 16) , 
    dest_sub_0x20+0x098 : int("0x10", 16) , 
    dest_sub_0x20+0x099 : int("0x20", 16) , 
    dest_sub_0x20+0x09A : int("0x0A", 16) , 
    dest_sub_0x20+0x09B : int("0x20", 16) , 
    dest_sub_0x20+0x09C : int("0x20", 16) , 
    dest_sub_0x20+0x09D : int("0x01", 16) , 
    dest_sub_0x20+0x09E : int("0x10", 16) , 
    dest_sub_0x20+0x09F : int("0x08", 16) , 
    dest_sub_0x20+0x0A0 : int("0x08", 16) , 
    dest_sub_0x20+0x0A1 : int("0x20", 16) , 
    dest_sub_0x20+0x0A2 : int("0x20", 16) , 
    dest_sub_0x20+0x0A3 : int("0x01", 16) , 
    dest_sub_0x20+0x0A4 : int("0x20", 16) , 
    dest_sub_0x20+0x0A5 : int("0x08", 16) , 
    dest_sub_0x20+0x0A6 : int("0x00", 16) , 
    dest_sub_0x20+0x0A7 : int("0x00", 16) , 
    dest_sub_0x20+0x0A8 : int("0x02", 16) , 
    dest_sub_0x20+0x0A9 : int("0x20", 16) , 
    dest_sub_0x20+0x0AA : int("0x00", 16) , 
    dest_sub_0x20+0x0AB : int("0x02", 16) , 
    dest_sub_0x20+0x0AC : int("0x02", 16) , 
    dest_sub_0x20+0x0AD : int("0x00", 16) , 
    dest_sub_0x20+0x0AE : int("0x02", 16) , 
    dest_sub_0x20+0x0AF : int("0x10", 16) , 
    dest_sub_0x20+0x0B0 : int("0x20", 16) , 
    dest_sub_0x20+0x0B1 : int("0x20", 16) , 
    dest_sub_0x20+0x0B2 : int("0x30", 16) , 
    dest_sub_0x20+0x0B3 : int("0x10", 16) , 
    dest_sub_0x20+0x0B4 : int("0x20", 16) , 
    dest_sub_0x20+0x0B5 : int("0x39", 16) , 
    dest_sub_0x20+0x0B6 : int("0x02", 16) , 
    dest_sub_0x20+0x0B7 : int("0x01", 16) , 
    dest_sub_0x20+0x0B8 : int("0x20", 16) , 
    dest_sub_0x20+0x0B9 : int("0x02", 16) , 
    dest_sub_0x20+0x0BA : int("0x80", 16) , 
    dest_sub_0x20+0x0BB : int("0x10", 16) , 
    dest_sub_0x20+0x0BC : int("0x20", 16) , 
    dest_sub_0x20+0x0BD : int("0x40", 16) , 
    dest_sub_0x20+0x0BE : int("0x02", 16) , 
    dest_sub_0x20+0x0BF : int("0x20", 16) , 
    dest_sub_0x20+0x0C0 : int("0x20", 16) , 
    dest_sub_0x20+0x0C1 : int("0x31", 16) , 
    dest_sub_0x20+0x0C2 : int("0x10", 16) , 
    dest_sub_0x20+0x0C3 : int("0x20", 16) , 
    dest_sub_0x20+0x0C4 : int("0xF8", 16) , 
    dest_sub_0x20+0x0C5 : int("0x02", 16) , 
    dest_sub_0x20+0x0C6 : int("0x01", 16) , 
    dest_sub_0x20+0x0C7 : int("0x20", 16) , 
    dest_sub_0x20+0x0C8 : int("0x02", 16) , 
    dest_sub_0x20+0x0C9 : int("0x80", 16) , 
    dest_sub_0x20+0x0CA : int("0x10", 16) , 
    dest_sub_0x20+0x0CB : int("0x20", 16) , 
    dest_sub_0x20+0x0CC : int("0x40", 16) , 
    dest_sub_0x20+0x0CD : int("0x02", 16) , 
    dest_sub_0x20+0x0CE : int("0x20", 16) , 
    dest_sub_0x20+0x0CF : int("0x20", 16) , 
    dest_sub_0x20+0x0D0 : int("0x32", 16) , 
    dest_sub_0x20+0x0D1 : int("0x10", 16) , 
    dest_sub_0x20+0x0D2 : int("0x20", 16) , 
    dest_sub_0x20+0x0D3 : int("0xE1", 16) , 
    dest_sub_0x20+0x0D4 : int("0x02", 16) , 
    dest_sub_0x20+0x0D5 : int("0x01", 16) , 
    dest_sub_0x20+0x0D6 : int("0x20", 16) , 
    dest_sub_0x20+0x0D7 : int("0x02", 16) , 
    dest_sub_0x20+0x0D8 : int("0x80", 16) , 
    dest_sub_0x20+0x0D9 : int("0x10", 16) , 
    dest_sub_0x20+0x0DA : int("0x20", 16) , 
    dest_sub_0x20+0x0DB : int("0x40", 16) , 
    dest_sub_0x20+0x0DC : int("0x02", 16) , 
    dest_sub_0x20+0x0DD : int("0x20", 16) , 
    dest_sub_0x20+0x0DE : int("0x20", 16) , 
    dest_sub_0x20+0x0DF : int("0x33", 16) , 
    dest_sub_0x20+0x0E0 : int("0x10", 16) , 
    dest_sub_0x20+0x0E1 : int("0x20", 16) , 
    dest_sub_0x20+0x0E2 : int("0x75", 16) , 
    dest_sub_0x20+0x0E3 : int("0x02", 16) , 
    dest_sub_0x20+0x0E4 : int("0x01", 16) , 
    dest_sub_0x20+0x0E5 : int("0x20", 16) , 
    dest_sub_0x20+0x0E6 : int("0x02", 16) , 
    dest_sub_0x20+0x0E7 : int("0x80", 16) , 
    dest_sub_0x20+0x0E8 : int("0x10", 16) , 
    dest_sub_0x20+0x0E9 : int("0x20", 16) , 
    dest_sub_0x20+0x0EA : int("0x40", 16) , 
    dest_sub_0x20+0x0EB : int("0x02", 16) , 
    dest_sub_0x20+0x0EC : int("0x20", 16) , 
    dest_sub_0x20+0x0ED : int("0x20", 16) , 
    dest_sub_0x20+0x0EE : int("0x34", 16) , 
    dest_sub_0x20+0x0EF : int("0x10", 16) , 
    dest_sub_0x20+0x0F0 : int("0x20", 16) , 
    dest_sub_0x20+0x0F1 : int("0x32", 16) , 
    dest_sub_0x20+0x0F2 : int("0x02", 16) , 
    dest_sub_0x20+0x0F3 : int("0x01", 16) , 
    dest_sub_0x20+0x0F4 : int("0x20", 16) , 
    dest_sub_0x20+0x0F5 : int("0x02", 16) , 
    dest_sub_0x20+0x0F6 : int("0x80", 16) , 
    dest_sub_0x20+0x0F7 : int("0x10", 16) , 
    dest_sub_0x20+0x0F8 : int("0x20", 16) , 
    dest_sub_0x20+0x0F9 : int("0x40", 16) , 
    dest_sub_0x20+0x0FA : int("0x02", 16) , 
    dest_sub_0x20+0x0FB : int("0x20", 16) , 
    dest_sub_0x20+0x0FC : int("0x20", 16) , 
    dest_sub_0x20+0x0FD : int("0x35", 16) , 
    dest_sub_0x20+0x0FE : int("0x10", 16) , 
    dest_sub_0x20+0x0FF : int("0x20", 16) , 
    dest_sub_0x20+0x100 : int("0x91", 16) , 
    dest_sub_0x20+0x101 : int("0x02", 16) , 
    dest_sub_0x20+0x102 : int("0x01", 16) , 
    dest_sub_0x20+0x103 : int("0x20", 16) , 
    dest_sub_0x20+0x104 : int("0x02", 16) , 
    dest_sub_0x20+0x105 : int("0x80", 16) , 
    dest_sub_0x20+0x106 : int("0x10", 16) , 
    dest_sub_0x20+0x107 : int("0x20", 16) , 
    dest_sub_0x20+0x108 : int("0x40", 16) , 
    dest_sub_0x20+0x109 : int("0x02", 16) , 
    dest_sub_0x20+0x10A : int("0x20", 16) , 
    dest_sub_0x20+0x10B : int("0x20", 16) , 
    dest_sub_0x20+0x10C : int("0x36", 16) , 
    dest_sub_0x20+0x10D : int("0x10", 16) , 
    dest_sub_0x20+0x10E : int("0x20", 16) , 
    dest_sub_0x20+0x10F : int("0xE8", 16) , 
    dest_sub_0x20+0x110 : int("0x02", 16) , 
    dest_sub_0x20+0x111 : int("0x01", 16) , 
    dest_sub_0x20+0x112 : int("0x20", 16) , 
    dest_sub_0x20+0x113 : int("0x02", 16) , 
    dest_sub_0x20+0x114 : int("0x80", 16) , 
    dest_sub_0x20+0x115 : int("0x10", 16) , 
    dest_sub_0x20+0x116 : int("0x20", 16) , 
    dest_sub_0x20+0x117 : int("0x40", 16) , 
    dest_sub_0x20+0x118 : int("0x02", 16) , 
    dest_sub_0x20+0x119 : int("0x20", 16) , 
    dest_sub_0x20+0x11A : int("0x20", 16) , 
    dest_sub_0x20+0x11B : int("0x37", 16) , 
    dest_sub_0x20+0x11C : int("0x10", 16) , 
    dest_sub_0x20+0x11D : int("0x20", 16) , 
    dest_sub_0x20+0x11E : int("0x22", 16) , 
    dest_sub_0x20+0x11F : int("0x02", 16) , 
    dest_sub_0x20+0x120 : int("0x01", 16) , 
    dest_sub_0x20+0x121 : int("0x20", 16) , 
    dest_sub_0x20+0x122 : int("0x02", 16) , 
    dest_sub_0x20+0x123 : int("0x80", 16) , 
    dest_sub_0x20+0x124 : int("0x10", 16) , 
    dest_sub_0x20+0x125 : int("0x20", 16) , 
    dest_sub_0x20+0x126 : int("0x40", 16) , 
    dest_sub_0x20+0x127 : int("0x02", 16) , 
    dest_sub_0x20+0x128 : int("0x20", 16) , 
    dest_sub_0x20+0x129 : int("0x20", 16) , 
    dest_sub_0x20+0x12A : int("0x38", 16) , 
    dest_sub_0x20+0x12B : int("0x10", 16) , 
    dest_sub_0x20+0x12C : int("0x20", 16) , 
    dest_sub_0x20+0x12D : int("0x22", 16) , 
    dest_sub_0x20+0x12E : int("0x02", 16) , 
    dest_sub_0x20+0x12F : int("0x01", 16) , 
    dest_sub_0x20+0x130 : int("0x20", 16) , 
    dest_sub_0x20+0x131 : int("0x02", 16) , 
    dest_sub_0x20+0x132 : int("0x80", 16) , 
    dest_sub_0x20+0x133 : int("0x10", 16) , 
    dest_sub_0x20+0x134 : int("0x20", 16) , 
    dest_sub_0x20+0x135 : int("0x40", 16) , 
    dest_sub_0x20+0x136 : int("0x02", 16) , 
    dest_sub_0x20+0x137 : int("0x20", 16) , 
    dest_sub_0x20+0x138 : int("0x20", 16) , 
    dest_sub_0x20+0x139 : int("0x39", 16) , 
    dest_sub_0x20+0x13A : int("0x10", 16) , 
    dest_sub_0x20+0x13B : int("0x20", 16) , 
    dest_sub_0x20+0x13C : int("0x8A", 16) , 
    dest_sub_0x20+0x13D : int("0x02", 16) , 
    dest_sub_0x20+0x13E : int("0x01", 16) , 
    dest_sub_0x20+0x13F : int("0x20", 16) , 
    dest_sub_0x20+0x140 : int("0x02", 16) , 
    dest_sub_0x20+0x141 : int("0x80", 16) , 
    dest_sub_0x20+0x142 : int("0x10", 16) , 
    dest_sub_0x20+0x143 : int("0x20", 16) , 
    dest_sub_0x20+0x144 : int("0x40", 16) , 
    dest_sub_0x20+0x145 : int("0x02", 16) , 
    dest_sub_0x20+0x146 : int("0x20", 16) , 
    dest_sub_0x20+0x147 : int("0x20", 16) , 
    dest_sub_0x20+0x148 : int("0x3A", 16) , 
    dest_sub_0x20+0x149 : int("0x10", 16) , 
    dest_sub_0x20+0x14A : int("0x20", 16) , 
    dest_sub_0x20+0x14B : int("0xDC", 16) , 
    dest_sub_0x20+0x14C : int("0x02", 16) , 
    dest_sub_0x20+0x14D : int("0x01", 16) , 
    dest_sub_0x20+0x14E : int("0x20", 16) , 
    dest_sub_0x20+0x14F : int("0x02", 16) , 
    dest_sub_0x20+0x150 : int("0x80", 16) , 
    dest_sub_0x20+0x151 : int("0x10", 16) , 
    dest_sub_0x20+0x152 : int("0x20", 16) , 
    dest_sub_0x20+0x153 : int("0x40", 16) , 
    dest_sub_0x20+0x154 : int("0x02", 16) , 
    dest_sub_0x20+0x155 : int("0x20", 16) , 
    dest_sub_0x20+0x156 : int("0x20", 16) , 
    dest_sub_0x20+0x157 : int("0x3B", 16) , 
    dest_sub_0x20+0x158 : int("0x10", 16) , 
    dest_sub_0x20+0x159 : int("0x20", 16) , 
    dest_sub_0x20+0x15A : int("0xAA", 16) , 
    dest_sub_0x20+0x15B : int("0x02", 16) , 
    dest_sub_0x20+0x15C : int("0x01", 16) , 
    dest_sub_0x20+0x15D : int("0x20", 16) , 
    dest_sub_0x20+0x15E : int("0x02", 16) , 
    dest_sub_0x20+0x15F : int("0x80", 16) , 
    dest_sub_0x20+0x160 : int("0x10", 16) , 
    dest_sub_0x20+0x161 : int("0x20", 16) , 
    dest_sub_0x20+0x162 : int("0x40", 16) , 
    dest_sub_0x20+0x163 : int("0x02", 16) , 
    dest_sub_0x20+0x164 : int("0x20", 16) , 
    dest_sub_0x20+0x165 : int("0x20", 16) , 
    dest_sub_0x20+0x166 : int("0x3C", 16) , 
    dest_sub_0x20+0x167 : int("0x10", 16) , 
    dest_sub_0x20+0x168 : int("0x20", 16) , 
    dest_sub_0x20+0x169 : int("0x83", 16) , 
    dest_sub_0x20+0x16A : int("0x02", 16) , 
    dest_sub_0x20+0x16B : int("0x01", 16) , 
    dest_sub_0x20+0x16C : int("0x20", 16) , 
    dest_sub_0x20+0x16D : int("0x02", 16) , 
    dest_sub_0x20+0x16E : int("0x80", 16) , 
    dest_sub_0x20+0x16F : int("0x10", 16) , 
    dest_sub_0x20+0x170 : int("0x20", 16) , 
    dest_sub_0x20+0x171 : int("0x40", 16) , 
    dest_sub_0x20+0x172 : int("0x02", 16) , 
    dest_sub_0x20+0x173 : int("0x20", 16) , 
    dest_sub_0x20+0x174 : int("0x20", 16) , 
    dest_sub_0x20+0x175 : int("0x3D", 16) , 
    dest_sub_0x20+0x176 : int("0x10", 16) , 
    dest_sub_0x20+0x177 : int("0x20", 16) , 
    dest_sub_0x20+0x178 : int("0xB7", 16) , 
    dest_sub_0x20+0x179 : int("0x02", 16) , 
    dest_sub_0x20+0x17A : int("0x01", 16) , 
    dest_sub_0x20+0x17B : int("0x20", 16) , 
    dest_sub_0x20+0x17C : int("0x02", 16) , 
    dest_sub_0x20+0x17D : int("0x80", 16) , 
    dest_sub_0x20+0x17E : int("0x10", 16) , 
    dest_sub_0x20+0x17F : int("0x20", 16) , 
    dest_sub_0x20+0x180 : int("0x40", 16) , 
    dest_sub_0x20+0x181 : int("0x02", 16) , 
    dest_sub_0x20+0x182 : int("0x20", 16) , 
    dest_sub_0x20+0x183 : int("0x20", 16) , 
    dest_sub_0x20+0x184 : int("0x3E", 16) , 
    dest_sub_0x20+0x185 : int("0x10", 16) , 
    dest_sub_0x20+0x186 : int("0x20", 16) , 
    dest_sub_0x20+0x187 : int("0x67", 16) , 
    dest_sub_0x20+0x188 : int("0x02", 16) , 
    dest_sub_0x20+0x189 : int("0x01", 16) , 
    dest_sub_0x20+0x18A : int("0x20", 16) , 
    dest_sub_0x20+0x18B : int("0x02", 16) , 
    dest_sub_0x20+0x18C : int("0x80", 16) , 
    dest_sub_0x20+0x18D : int("0x10", 16) , 
    dest_sub_0x20+0x18E : int("0x20", 16) , 
    dest_sub_0x20+0x18F : int("0x40", 16) , 
    dest_sub_0x20+0x190 : int("0x02", 16) , 
    dest_sub_0x20+0x191 : int("0x20", 16) , 
    dest_sub_0x20+0x192 : int("0x20", 16) , 
    dest_sub_0x20+0x193 : int("0x3F", 16) , 
    dest_sub_0x20+0x194 : int("0x10", 16) , 
    dest_sub_0x20+0x195 : int("0x20", 16) , 
    dest_sub_0x20+0x196 : int("0x83", 16) , 
    dest_sub_0x20+0x197 : int("0x02", 16) , 
    dest_sub_0x20+0x198 : int("0x01", 16) , 
    dest_sub_0x20+0x199 : int("0x20", 16) , 
    dest_sub_0x20+0x19A : int("0x02", 16) , 
    dest_sub_0x20+0x19B : int("0x80", 16) , 
    dest_sub_0x20+0x19C : int("0x10", 16) , 
    dest_sub_0x20+0x19D : int("0x20", 16) , 
    dest_sub_0x20+0x19E : int("0x40", 16) , 
    dest_sub_0x20+0x19F : int("0x02", 16) , 
    dest_sub_0x20+0x1A0 : int("0x20", 16) , 
    dest_sub_0x20+0x1A1 : int("0x20", 16) , 
    dest_sub_0x20+0x1A2 : int("0x40", 16) , 
    dest_sub_0x20+0x1A3 : int("0x10", 16) , 
    dest_sub_0x20+0x1A4 : int("0x20", 16) , 
    dest_sub_0x20+0x1A5 : int("0xAD", 16) , 
    dest_sub_0x20+0x1A6 : int("0x02", 16) , 
    dest_sub_0x20+0x1A7 : int("0x01", 16) , 
    dest_sub_0x20+0x1A8 : int("0x20", 16) , 
    dest_sub_0x20+0x1A9 : int("0x02", 16) , 
    dest_sub_0x20+0x1AA : int("0x80", 16) , 
    dest_sub_0x20+0x1AB : int("0x10", 16) , 
    dest_sub_0x20+0x1AC : int("0x20", 16) , 
    dest_sub_0x20+0x1AD : int("0x40", 16) , 
    dest_sub_0x20+0x1AE : int("0x02", 16) , 
    dest_sub_0x20+0x1AF : int("0x20", 16) , 
    dest_sub_0x20+0x1B0 : int("0x20", 16) , 
    dest_sub_0x20+0x1B1 : int("0x41", 16) , 
    dest_sub_0x20+0x1B2 : int("0x10", 16) , 
    dest_sub_0x20+0x1B3 : int("0x20", 16) , 
    dest_sub_0x20+0x1B4 : int("0x8D", 16) , 
    dest_sub_0x20+0x1B5 : int("0x02", 16) , 
    dest_sub_0x20+0x1B6 : int("0x01", 16) , 
    dest_sub_0x20+0x1B7 : int("0x20", 16) , 
    dest_sub_0x20+0x1B8 : int("0x02", 16) , 
    dest_sub_0x20+0x1B9 : int("0x80", 16) , 
    dest_sub_0x20+0x1BA : int("0x10", 16) , 
    dest_sub_0x20+0x1BB : int("0x20", 16) , 
    dest_sub_0x20+0x1BC : int("0x40", 16) , 
    dest_sub_0x20+0x1BD : int("0x02", 16) , 
    dest_sub_0x20+0x1BE : int("0x20", 16) , 
    dest_sub_0x20+0x1BF : int("0x20", 16) , 
    dest_sub_0x20+0x1C0 : int("0x42", 16) , 
    dest_sub_0x20+0x1C1 : int("0x10", 16) , 
    dest_sub_0x20+0x1C2 : int("0x20", 16) , 
    dest_sub_0x20+0x1C3 : int("0xF6", 16) , 
    dest_sub_0x20+0x1C4 : int("0x02", 16) , 
    dest_sub_0x20+0x1C5 : int("0x01", 16) , 
    dest_sub_0x20+0x1C6 : int("0x20", 16) , 
    dest_sub_0x20+0x1C7 : int("0x02", 16) , 
    dest_sub_0x20+0x1C8 : int("0x80", 16) , 
    dest_sub_0x20+0x1C9 : int("0x10", 16) , 
    dest_sub_0x20+0x1CA : int("0x20", 16) , 
    dest_sub_0x20+0x1CB : int("0x40", 16) , 
    dest_sub_0x20+0x1CC : int("0x02", 16) , 
    dest_sub_0x20+0x1CD : int("0x20", 16) , 
    dest_sub_0x20+0x1CE : int("0x20", 16) , 
    dest_sub_0x20+0x1CF : int("0x43", 16) , 
    dest_sub_0x20+0x1D0 : int("0x10", 16) , 
    dest_sub_0x20+0x1D1 : int("0x20", 16) , 
    dest_sub_0x20+0x1D2 : int("0x06", 16) , 
    dest_sub_0x20+0x1D3 : int("0x02", 16) , 
    dest_sub_0x20+0x1D4 : int("0x01", 16) , 
    dest_sub_0x20+0x1D5 : int("0x20", 16) , 
    dest_sub_0x20+0x1D6 : int("0x02", 16) , 
    dest_sub_0x20+0x1D7 : int("0x80", 16) , 
    dest_sub_0x20+0x1D8 : int("0x10", 16) , 
    dest_sub_0x20+0x1D9 : int("0x20", 16) , 
    dest_sub_0x20+0x1DA : int("0x40", 16) , 
    dest_sub_0x20+0x1DB : int("0x02", 16) , 
    dest_sub_0x20+0x1DC : int("0x20", 16) , 
    dest_sub_0x20+0x1DD : int("0x20", 16) , 
    dest_sub_0x20+0x1DE : int("0x44", 16) , 
    dest_sub_0x20+0x1DF : int("0x10", 16) , 
    dest_sub_0x20+0x1E0 : int("0x20", 16) , 
    dest_sub_0x20+0x1E1 : int("0xBA", 16) , 
    dest_sub_0x20+0x1E2 : int("0x02", 16) , 
    dest_sub_0x20+0x1E3 : int("0x01", 16) , 
    dest_sub_0x20+0x1E4 : int("0x20", 16) , 
    dest_sub_0x20+0x1E5 : int("0x02", 16) , 
    dest_sub_0x20+0x1E6 : int("0x80", 16) , 
    dest_sub_0x20+0x1E7 : int("0x10", 16) , 
    dest_sub_0x20+0x1E8 : int("0x20", 16) , 
    dest_sub_0x20+0x1E9 : int("0x40", 16) , 
    dest_sub_0x20+0x1EA : int("0x02", 16) , 
    dest_sub_0x20+0x1EB : int("0x10", 16) , 
    dest_sub_0x20+0x1EC : int("0x02", 16) , 
    dest_sub_0x20+0x1ED : int("0x00", 16) , 
    dest_sub_0x20+0x1EE : int("0x02", 16) , 
    dest_sub_0x20+0x1EF : int("0x02", 16) , 
    dest_sub_0x20+0x1F0 : int("0x00", 16) , 
    dest_sub_0x20+0x1F1 : int("0x20", 16) , 
    dest_sub_0x20+0x1F2 : int("0x02", 16) , 
    dest_sub_0x20+0x1F3 : int("0x00", 16) , 
    dest_sub_0x20+0x1F4 : int("0x04", 16) , 
    dest_sub_0x20+0x1F5 : int("0x20", 16) , 
    dest_sub_0x20+0x1F6 : int("0xB2", 16) , 
    dest_sub_0x20+0x1F7 : int("0x02", 16) , 
    dest_sub_0x20+0x1F8 : int("0x20", 16) , 
    dest_sub_0x20+0x1F9 : int("0x9B", 16) , 
    dest_sub_0x20+0x1FA : int("0x10", 16) , 
    dest_sub_0x20+0x1FB : int("0x20", 16) , 
    dest_sub_0x20+0x1FC : int("0x1C", 16) , 
    dest_sub_0x20+0x1FD : int("0x20", 16) , 
    dest_sub_0x20+0x1FE : int("0x20", 16) , 
    dest_sub_0x20+0x1FF : int("0x01", 16) , 
    dest_sub_0x20+0x200 : int("0x10", 16) , 
    dest_sub_0x20+0x201 : int("0x08", 16) , 
    dest_sub_0x20+0x202 : int("0x08", 16) , 
    dest_sub_0x20+0x203 : int("0x20", 16) , 
    dest_sub_0x20+0x204 : int("0x20", 16) , 
    dest_sub_0x20+0x205 : int("0xC6", 16) , 
    dest_sub_0x20+0x206 : int("0x02", 16) , 
    dest_sub_0x20+0x207 : int("0x20", 16) , 
    dest_sub_0x20+0x208 : int("0x00", 16) , 
    dest_sub_0x20+0x209 : int("0x01", 16) , 
    dest_sub_0x20+0x20A : int("0x08", 16) , 
    dest_sub_0x20+0x20B : int("0x08", 16) , 
    dest_sub_0x20+0x20C : int("0x02", 16) , 
    dest_sub_0x20+0x20D : int("0x20", 16) , 
    dest_sub_0x20+0x20E : int("0x00", 16) , 
    dest_sub_0x20+0x20F : int("0x02", 16) , 
    dest_sub_0x20+0x210 : int("0x80", 16) , 
    dest_sub_0x20+0x211 : int("0x01", 16) , 
    dest_sub_0x20+0x212 : int("0x10", 16) , 
    dest_sub_0x20+0x213 : int("0x20", 16) , 
    dest_sub_0x20+0x214 : int("0xFF", 16) , 
    dest_sub_0x20+0x215 : int("0x20", 16) , 
    dest_sub_0x20+0x216 : int("0x20", 16) , 
    dest_sub_0x20+0x217 : int("0x00", 16) , 
    dest_sub_0x20+0x218 : int("0x20", 16) , 
    dest_sub_0x20+0x219 : int("0x80", 16) , 
    dest_sub_0x20+0x21A : int("0x08", 16) , 
    dest_sub_0x20+0x21B : int("0x02", 16) , 
    dest_sub_0x20+0x21C : int("0x08", 16) , 
    dest_sub_0x20+0x21D : int("0x08", 16) , 
    dest_sub_0x20+0x21E : int("0x02", 16) , 
    dest_sub_0x20+0x21F : int("0x20", 16) , 
    dest_sub_0x20+0x220 : int("0x00", 16) , 
    dest_sub_0x20+0x221 : int("0x02", 16) , 
    dest_sub_0x20+0x222 : int("0x80", 16) , 
    dest_sub_0x20+0x223 : int("0x01", 16) , 
    dest_sub_0x20+0x224 : int("0x10", 16) , 
    dest_sub_0x20+0x225 : int("0x20", 16) , 
    dest_sub_0x20+0x226 : int("0x00", 16) , 
    dest_sub_0x20+0x227 : int("0x10", 16) , 
    dest_sub_0x20+0x228 : int("0x80", 16) , 
    dest_sub_0x20+0x229 : int("0x08", 16) , 
    dest_sub_0x20+0x22A : int("0x20", 16) , 
    dest_sub_0x20+0x22B : int("0x20", 16) , 
    dest_sub_0x20+0x22C : int("0x01", 16) , 
    dest_sub_0x20+0x22D : int("0x10", 16) , 
    dest_sub_0x20+0x22E : int("0x08", 16) , 
    dest_sub_0x20+0x22F : int("0x08", 16) , 
    dest_sub_0x20+0x230 : int("0x20", 16) , 
    dest_sub_0x20+0x231 : int("0x20", 16) , 
    dest_sub_0x20+0x232 : int("0x00", 16) , 
    dest_sub_0x20+0x233 : int("0x20", 16) , 
    dest_sub_0x20+0x234 : int("0x08", 16) , 
    dest_sub_0x20+0x235 : int("0x00", 16) , 
    dest_sub_0x20+0x236 : int("0x20", 16) , 
    dest_sub_0x20+0x237 : int("0x20", 16) , 
    dest_sub_0x20+0x238 : int("0x30", 16) , 
    dest_sub_0x20+0x239 : int("0x02", 16) , 
    dest_sub_0x20+0x23A : int("0x20", 16) , 
    dest_sub_0x20+0x23B : int("0x86", 16) , 
    dest_sub_0x20+0x23C : int("0x10", 16) , 
    dest_sub_0x20+0x23D : int("0x20", 16) , 
    dest_sub_0x20+0x23E : int("0x15", 16) , 
    dest_sub_0x20+0x23F : int("0x08", 16) , 
    dest_sub_0x20+0x240 : int("0x20", 16) , 
    dest_sub_0x20+0x241 : int("0x02", 16) , 
    dest_sub_0x20+0x242 : int("0x08", 16) , 
    dest_sub_0x20+0x243 : int("0x80", 16) , 
    dest_sub_0x20+0x244 : int("0x04", 16) , 
    dest_sub_0x20+0x245 : int("0x00", 16) , 
    dest_sub_0x20+0x246 : int("0x02", 16) , 
    dest_sub_0x20+0x247 : int("0x08", 16) , 
    dest_sub_0x20+0x248 : int("0x04", 16) , 
    dest_sub_0x20+0x249 : int("0x20", 16) , 
    dest_sub_0x20+0x24A : int("0x11", 16) , 
    dest_sub_0x20+0x24B : int("0x10", 16) , 
    dest_sub_0x20+0x24C : int("0x20", 16) , 
    dest_sub_0x20+0x24D : int("0x00", 16) , 
    dest_sub_0x20+0x24E : int("0x08", 16) , 
    dest_sub_0x20+0x24F : int("0x04", 16) , 
    dest_sub_0x20+0x250 : int("0x10", 16) , 
    dest_sub_0x20+0x251 : int("0x08", 16) , 
    dest_sub_0x20+0x252 : int("0x20", 16) , 
    dest_sub_0x20+0x253 : int("0x9D", 16) , 
    dest_sub_0x20+0x254 : int("0x02", 16) , 
    dest_sub_0x20+0x255 : int("0x10", 16) , 
    dest_sub_0x20+0x256 : int("0x08", 16) , 
    dest_sub_0x20+0x257 : int("0x08", 16) , 
    dest_sub_0x20+0x258 : int("0x20", 16) , 
    dest_sub_0x20+0x259 : int("0x27", 16) , 
    dest_sub_0x20+0x25A : int("0x11", 16) , 
    dest_sub_0x20+0x25B : int("0x10", 16) , 
    dest_sub_0x20+0x25C : int("0x08", 16) , 
    dest_sub_0x20+0x25D : int("0x00", 16) , 
    dest_sub_0x20+0x25E : int("0x00", 16) , 
    dest_sub_0x20+0x25F : int("0x00", 16) , 
}

dic_mem = {
    vm_mem_sub_0x280+0x280 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x288 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x290 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x298 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x2A0 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x2A8 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x2B0 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x2B8 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x2C0 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x2C8 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x2D0 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x2D8 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x2E0 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x2E8 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x2F0 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x2F8 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x300 : "0390AED3A08E1914" ,      
    vm_mem_sub_0x280+0x308 : "074BE9EBAE7B2B1F" ,      
    vm_mem_sub_0x280+0x310 : "F0B93CBE5B609C02" ,    
    vm_mem_sub_0x280+0x318 : "4552524F4326E336" ,     
    vm_mem_sub_0x280+0x320 : "6572654820215443" ,     
    vm_mem_sub_0x280+0x328 : "72756F7920736920" ,     
    vm_mem_sub_0x280+0x330 : "490A3A67616C6620" ,     
    vm_mem_sub_0x280+0x338 : "54434552524F434E" ,     
    vm_mem_sub_0x280+0x340 : "662F203A59454B21" ,     
    vm_mem_sub_0x280+0x348 : "000000000067616c" ,               
    vm_mem_sub_0x280+0x350 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x358 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x360 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x368 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x370 : "0000000000000000" ,                     
    vm_mem_sub_0x280+0x378 : "0000000000000000" ,                                         
}

def init_quaword(arr, quadword_str, index):
  for i in range(8):
    arr[index + i] = int(quadword_str[(14 - i*2):][:2], 16)

def copy_mem_to_dest(mem, dic_mem, index):
  global a1_arr
  mem_copy = mem 
  for i in range(len(dic_mem)):
    quadword_str = dic_mem[mem_copy]
    init_quaword(a1_arr, quadword_str, index + i * 8)
    mem_copy += 0x8

def memcpy_dest_vmcode(dest, dic_dest):
    dest_copy = dest
    for i in  range(len(dic_dest)):
        a1_arr[i] = dic_dest[dest_copy]
        dest_copy += 1
    
def table_aAbcdsif(value):
    if value == 0x555555557024:
        return 0x61
    elif value == 0x555555557026:
        return 0x62
    elif value == 0x555555557028:
        return 0x63
    elif value == 0x55555555702A:
        return 0x64
    elif value == 0x55555555702C:
        return 0x73
    elif value == 0x55555555702E:
        return 0x69
    elif value == 0x555555557030:
        return 0x66
    elif value == 0x555555557032:
        return 0x4E
    else:
        error("table_aAbcdsif error!!" + hex(value))


def print_a1_arr():
    global a1_arr
    for i in range(len(a1_arr)):
        if a1_arr[i] != None:
            print(f"a1[{i}] = {a1_arr[i]}", end=" ")


def print_a1_1024():
    global a1_1024
    for i in range(len(a1_1024)):
        try:
            print(f"a1[{1024 + i}] = " + str(hex(a1_1024[i])), end=" ")
        except:
            print(a1_1024[i], end=" ")


def print_arr():
    print_a1_1024()
    print("\n")
    #print_a1_arr()
    #print("\n")

def print_arr_all():
    print_a1_1024()
    print("\n")
    print_a1_arr()
    print("\n")

"""
0x555555557024: 0x61
0x555555557026: 0x62
0x555555557028: 0x63
0x55555555702a: 0x64
0x55555555702c: 0x73 s
0x55555555702e: 0x69 i
0x555555557030: 0x66 f
0x555555557032: 0x4e N
"""

def describe_register(str):
    global aAbcdsif
    if str == 32:
        return aAbcdsif
    elif str == 2:
        return aAbcdsif + 2 * 1
    elif str == 16:
        return aAbcdsif + 2 * 2
    elif str == 8:
        return aAbcdsif + 2 * 3
    elif str == 1:
        return aAbcdsif + 2 * 4
    elif str == 4:
        return aAbcdsif + 2 * 5
    elif str == 64:
        return aAbcdsif + 2 * 6
    elif str:
        return aAbcdsif + 19
    else:
        return aAbcdsif + 2 * 7


def write_register(a1, a2, a3):
    global a1_1024
    if a2 == 32:
        res = a1
        a1_1024[0] = a3
        return res
    elif a2 == 2:
        res = a1
        a1_1024[1] = a3
        return res
    elif a2 == 16:
        res = a1
        a1_1024[2] = a3
        return res
    elif a2 == 8:
        res = a1
        a1_1024[3] = a3
        return res
    elif a2 == 1:
        res = a1
        a1_1024[4] = a3
        return res
    elif a2 == 4:
        res = a1
        a1_1024[5] = a3
        return res
    elif a2 == 64:
        res = a1
        a1_1024[6] = a3
        return res
    else:
        error("Error write_register")


def read_register(a1, x):

    if x == 32:
        return a1_1024[0]
    elif x == 2:
        return a1_1024[1]
    elif x == 16:
        return a1_1024[2]
    elif x == 8:
        return a1_1024[3]
    elif x == 1:
        return a1_1024[4]
    elif x == 4:
        return a1_1024[5]
    elif x != 64:
        error("read_register!!!")
    else:
        return a1_1024[6]

def write_memory(a1, x, y):
    global a1_arr
    res = x
    a1_arr[x + 768] = y
    return res

def read_memory(a1, a2):
    global a1_arr
    return a1_arr[a2 + 768]


def describe_flags(a1):
    global flag_description_arr
    global flag_description
    
    v2 = 0
    
    if a1 & 0x2 != 0:
        flag_description_arr[0] = 76
        v2 = 1
    
    if a1 & 0x4 != 0:
        flag_description_arr[v2] = 71
        v2 = v2 + 1
    
    if a1 & 0x8 != 0:
        flag_description_arr[v2] = 69
        v2 = v2 + 1
    
    if a1 & 0x1 != 0:
        flag_description_arr[v2] = 78
        v2 = v2 + 1
    
    if a1 & 0x10 != 0:
        flag_description_arr[v2] = 90
        v2 = v2 + 1
    
    if a1 == 0:
        flag_description_arr[v2] = 42
        v2 = v2 + 1
    
    flag_description_arr[v2] = 0
    return flag_description     
        
def table_describe_flags():
    global flag_description_arr
    global flag_description 
    res = ''
    for char in flag_description_arr:
        try:    
            res += chr(char)
        except:
            pass
        
    return res
        
        

def interpret_imm(a1, a2_hex_arr):
    info("IMM")
    v2 = describe_register(a2_hex_arr[0])
    print(f"IMM {chr(table_aAbcdsif(v2))} = {hex(a2_hex_arr[2])}")
    write_register(a1, a2_hex_arr[0], a2_hex_arr[2])
    print_arr()


def interpret_add(a1, a2_hex_arr):
    info("ADD")
    v2 = describe_register(a2_hex_arr[2])
    v3 = describe_register(a2_hex_arr[0])
    print(f"[s] ADD {chr(table_aAbcdsif(v3))}  {chr(table_aAbcdsif(v2))}")
    v2 = read_register(a1, a2_hex_arr[0])
    v4 = read_register(a1, a2_hex_arr[2])
    #problem happens when v2 + v4 > 0x100
    if v2 + v4 > 0x100:
        sum = v2 + v4 - 0x100
    else:
        sum = v2 + v4
    write_register(a1, a2_hex_arr[0], sum)
    print_arr()

def interpret_stk(a1, a2_hex_arr):
    info("STK")
    global a1_1024
    v2 = describe_register(a2_hex_arr[2])
    v3 = describe_register(a2_hex_arr[0])
    print(f"[s] STK {chr(table_aAbcdsif(v3))}  {chr(table_aAbcdsif(v2))}")
    
    if a2_hex_arr[2]:
        v4 =  describe_register(a2_hex_arr[2])
        print(f"[s] ... pushing {chr(table_aAbcdsif(v4))}")
        a1_1024[4] += 1 
        v5 = read_register(a1, a2_hex_arr[2])
        write_memory(a1, a1_1024[4], v5)
        
    result = a2_hex_arr[2]
    
    if a2_hex_arr[0]:
        v7 = describe_register(a2_hex_arr[0])
        print(f"[s] ... popping {chr(table_aAbcdsif(v7))}")
        memory = read_memory(a1, a1_1024[4])
        write_register(a1, a2_hex_arr[0], memory)
        result = a1
        a1_1024[4] -= 1
    
    print_arr()
    return result

def interpret_stm(a1, a2_hex_arr):
    info("STM")
    v2 = describe_register(a2_hex_arr[2])
    v3 = describe_register(a2_hex_arr[0])
    print(f"[s] STM *{chr(table_aAbcdsif(v3))} = {chr(table_aAbcdsif(v2))}")
    v2 = read_register(a1, a2_hex_arr[2])
    v4 = read_register(a1, a2_hex_arr[0])
    write_memory(a1, v4, v2)
    print_arr()

def interpret_ldm(a1, a2_hex_arr):
    info("LDM")
    v2 = describe_register(a2_hex_arr[2])
    v3 = describe_register(a2_hex_arr[0])  
    print(f"[s] LDM {chr(table_aAbcdsif(v3))} = *{chr(table_aAbcdsif(v2))}")
    v4 = read_register(a1, a2_hex_arr[2])
    memory = read_memory(a1, v4)
    info("v4 @ " + hex(v4))
    info("memory @ " + hex(memory))
    write_register(a1, a2_hex_arr[0], memory)
    print_arr()

def interpret_cmp(a1, a2_hex_arr):
    info("CMP")
    global a1_1024
    global license_key
    v2 = describe_register(a2_hex_arr[2])
    v3 = describe_register(a2_hex_arr[0])   
    print(f"[s] CMP {chr(table_aAbcdsif(v3))} = {chr(table_aAbcdsif(v2))}")
    
    v5 = read_register(a1, a2_hex_arr[0])
    v6 = read_register(a1, a2_hex_arr[2])
    a1_1024[6] = 0
    if v5 < v6:
        a1_1024[6] |= 0x1
        
    if v5 > v6:
        a1_1024[6] |= 0x10
    
    if v5 == v6:
        a1_1024[6] |= 0x2
    
    result = v5

    if v5 != v6:
        result = a1
        a1_1024[6] |= 0x4
    
    if v5 == 0 and v6 == 0:
        result = a1
        a1_1024[6] |= 0x8
    
    print_arr()
    return result       

def interpret_jmp(a1, a2_hex_arr):
    info("JMP")
    global a1_1024  
    v2 = describe_register(a2_hex_arr[2])
    v3 = describe_flags(a2_hex_arr[0])  
    print(f"[j] JMP {table_describe_flags()} {chr(table_aAbcdsif(v2))}")   
    
    if a2_hex_arr[0] != 0  and a2_hex_arr[0] & a1_1024[6] == 0:
        print_arr()
        return print("[j] ... NOT TAKEN")
    
    print("[j] ... TAKEN")
    
    result = read_register(a1, a2_hex_arr[2])
    a1_1024[5] = result
    print_arr()
    return result
    
def interpret_sys(a1, a2_hex_arr):
    info("SYS")    
    
    v2 = describe_register(a2_hex_arr[2])
    print(f"[s] SYS {hex(a2_hex_arr[0])} {chr(table_aAbcdsif(v2))}")
    
    a2_and_option = a2_hex_arr[0]
    
    if((a2_and_option & 0x2) != 0):
        print("[s] ... read_memory")
        v6 = a1_1024[2]
        if (256 - a1_1024[1] <= v6):
            v6 = -a1_1024[1]
            
        read_input = input("input: ")[:v6]
        for i in range (len(read_input)):
            a1_arr[a1_1024[1] + i + 768] = ord(read_input[i])      
        write_register(a1, a2_hex_arr[2], len(read_input))
    
    if((a2_and_option & 0x10) != 0):
        print("[s] ... write")
        v8 = a1_1024[2]
        if(256 - a1_1024[1] <= v8):
            v8 = - a1_1024[1]
        print(a1_arr[a1_1024[1] + 768])
        write_register(a1, a2_hex_arr[2], 5)        
    
    result = a2_hex_arr[0] & 0x20
    
    if((a2_and_option & 0x20) != 0):
        print("[s] ... exit")
        exit(a1_1024[0])
    
    if(a2_hex_arr[2]):
        v12 = read_register(a1, a2_hex_arr[2])
        v13 = describe_register(a2_hex_arr[2])
        print(
            f"[s] ... return value (in register {chr(table_aAbcdsif(v13))}): {hex(v12)}\n"
        )
        return print_arr()
    
    print_arr()
    return result  

def interpret_instruction(a1, a2):
    print(
        f"[V] a:{hex(a1_1024[0])} b:{hex(a1_1024[1])} c:{hex(a1_1024[2])} d:{hex(a1_1024[3])} s:{hex(a1_1024[4])} i:{hex(a1_1024[5])} f:{hex(a1_1024[6])}"
    )
    a2_hex_str = f"{a2:02x}".zfill(6)

    a2_hex_arr = [None] * 3
    op = a2_hex_arr[1] = int(a2_hex_str[2:4], 16)
    arg2 = a2_hex_arr[2] = int(a2_hex_str[0:2], 16)
    arg1 = a2_hex_arr[0] = int(a2_hex_str[4:6], 16)

    print(f"[I] op:{hex(op)} arg1:{hex(arg1)} arg2:{hex(arg2)}")

    if op & 0x20 != 0:
        interpret_imm(a1, a2_hex_arr)
        
    if op & 0x80 != 0:
        interpret_add(a1, a2_hex_arr)
        
    if op & 0x2 != 0:
        interpret_stk(a1, a2_hex_arr)  

    if op & 0x40 != 0:
        interpret_stm(a1, a2_hex_arr)          
    
    if op & 0x1 != 0:
        interpret_ldm(a1, a2_hex_arr)   

    if op & 0x4 != 0:
        interpret_cmp(a1, a2_hex_arr) 
  
    if op & 0x10 != 0:
        interpret_jmp(a1, a2_hex_arr)   
        
    result = op & 8
    
    if op & 0x8 != 0:
        return interpret_sys(a1, a2_hex_arr)
    
    return result

def interpreter_loop(a1):
    global a1_arr
    global a1_1024
    print("[+] Starting interpreter loop! Good luck!")
    while True:
        v1 = a1_1024[5]
        a1_1024[5] = v1 + 1
        success("v1 @ " + hex(v1))
        x = a1_arr[3 * v1] | (a1_arr[3 * v1 + 1] << 8)
        y = (a1_arr[3 * v1 + 2] << 16)
        success("x | y @ " + hex(x | y))
        interpret_instruction(a1, x | y)
        

memcpy_dest_vmcode(dest, dic_dest)
copy_mem_to_dest(vm_mem, dic_mem, 96 * 8)
print_arr()
interpreter_loop(a1)
