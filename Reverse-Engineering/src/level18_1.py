#!/usr/bin/env python3
from pwn import *

context.log_level = "info"
context.binary = elf = ELF("/challenge/babyrev_level18.1", checksec=False)

# libc = ELF('', checksec=False)
libc = elf.libc

gs = """
b *0x5555555559ef
b *0x555555556d73
b *0x55555555598c
b *0x5555555561f1
"""


def info(mess):
    return log.info(mess)


def success(mess):
    return log.success(mess)


def error(mess):
    log.error(mess)


def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path}, gdbscript=gs)
    elif args.REMOTE:
        return remote(
            "",
        )
    else:
        return process(elf.path, env={"LD_LIBRARY_PATH": libc.path})


a1 = 0x7fffffffddf0
a1_256 = [None] * 7
a1_arr = [None] * 300



def print_a1_arr():
    global a1_arr
    for i in range(len(a1_arr)):
        if a1_arr[i] != None:
            print(f"a1[{i}] = {a1_arr[i]}", end=" ")


def print_a1_256():
    global a1_256
    for i in range(len(a1_256)):
        try:
            print(f"a1[{256 + i}] = " + str(a1_256[i]), end=" ")
        except:
            print(a1_256[i], end=" ")


def print_arr():
    print_a1_256()
    print("\n")
    print_a1_arr()
    print("\n")


def write_register(a1, a2, a3):
    global a1_256
    if a2 == 1:
        res = a1
        a1_256[0] = a3
        return res
    elif a2 == 32:
        res = a1
        a1_256[1] = a3
        return res
    elif a2 == 16:
        res = a1
        a1_256[2] = a3
        return res
    elif a2 == 2:
        res = a1
        a1_256[3] = a3
        return res
    elif a2 == 8:
        res = a1
        a1_256[4] = a3
        return res
    elif a2 == 4:
        res = a1
        a1_256[5] = a3
        return res
    elif a2 == 64:
        res = a1
        a1_256[6] = a3
        return res
    else:
        error("Error write_register")


def read_register(a1, x):
     
    if x == 1:
            return a1_256[0]
    elif x == 32:
            return a1_256[1]
    elif x == 16:
            return a1_256[2]
    elif x == 2:
            return a1_256[3]
    elif x == 8:
            return a1_256[4]
    elif x == 4:
            return a1_256[5]
    elif x != 64:
        error("read_register!!!")
    else:
        return a1_256[6]


def write_memory(a1, x, y):
    global a1_arr
    res = x
    a1_arr[x] = y
    return res

def read_memory(a1, a2):
    global a1_arr
    return a1_arr[a2]

def sys_open(a1, a2, a3):
    return open(a2, a3)

def sys_read(a1, a2, a3, a4):
    return 

def interpret_imm(a1, a2, a3):
    info("IMM")
    print("return of interpret_imm: " + hex(write_register(a1, a2, a3)))
    print_arr()


def interpret_stm(a1, a2, a3):
    info("STM")
    v3 = read_register(a1, a3)
    v5 = read_register(a1, a2)
    write_memory(a1, v5, v3)
    print_arr()


def interpret_add(a1, a2, a3):
    info("ADD")
    v3 = read_register(a1, a2)
    v5 = read_register(a1, a3)
    write_register(a1, a2, v3 + v5)
    print_arr()

def interpret_sys(a1, a2, a3): 
    info("SYS")     
    if((a2 & 0x20) != 0):
        print("[s] ... read_memory")
        v5 = a1_256[2]
        if (256 - a1_256[1] <= v5):
        #0x555555555dae <interpret_sys+263>    cmp    rdx, rax                        0xa8 - 0x4     EFLAGS => 0x202 [ cf pf af zf sf IF df of ]
        #0x555555555db1 <interpret_sys+266>    cmovbe rax, rdx
            v5 = -a1_256[1]
            
        read_input = input("input: ")[:v5]
        for i in range (len(read_input)):
            a1_arr[a1_256[1] + i] = ord(read_input[i])
            write_register(a1, a3, len(read_input))
    
    if((a2 & 0x2) != 0):
        print("[s] ... write")
        v7 = a1_256[2]
        if(256 - a1_256[1] <= v7):
            v7 = - a1_256[1]
        print(a1_arr[a1_256[1]])
        write_register(a1, a3, 1)
    
    result = a2 & 0x20
    
    if((a2 & 0x4) != 0):
        print("[s] ... exit")
        exit(a1_256[1])
    print_arr()
    return result
 
def interpret_ldm(a1, a2, a3):
    info("LDM")   
    v5 = read_register(a1, a3)
    memory = read_memory(a1, v5)
    if(memory == None):
        memory = 0
    write_register(a1, a2, memory)   
    print_arr() 

        
def interpret_cmp(a1, a2, a3):
    global a1_arr
    global a1_256
    info("CMP")      
    v7 = read_register(a1, a2)
    v8 = read_register(a1, a3)
    a1_256[6] = 0
    if(v7 < v8):
        a1_256[6] |= 1
    if(v7 > v8):
        a1_256[6] |= 0x10
    if(v7 == v8):
        a1_256[6] |= 2
    result = v7
    
    if(v7 != v8):
        result = a1
        a1_256[6] |= 4
    
    if(v7 == 0) and (v8 == 0):
        result = a1
        a1_256[6] |= 8
    
    print_arr()
    return result
     
        
def ans():
    global a1_arr
    res = ""
    for i in range(128, 140):
        res += f"{a1_arr[i]:02x}"[-2:]
    
    info(res)
    return bytes.fromhex(res)

interpret_imm(a1, 32, 96)
interpret_imm(a1, 16, 12)
interpret_imm(a1, 1, 0)
interpret_sys(a1, 32, 1)
interpret_imm(a1, 32, 128)
interpret_imm(a1, 16, 1)
interpret_imm(a1, 1, 170)
interpret_stm(a1, 32, 1)
interpret_add(a1, 32, 16)
interpret_imm(a1, 1, 150)
interpret_stm(a1, 32, 1)
interpret_add(a1, 32, 16)
interpret_imm(a1, 1, 100)#
interpret_stm(a1, 32, 1)
interpret_add(a1, 32, 16)
interpret_imm(a1, 1, 106)
interpret_stm(a1, 32, 1)
interpret_add(a1, 32, 16)
interpret_imm(a1, 1, 11)
interpret_stm(a1, 32, 1)
interpret_add(a1, 32, 16)
interpret_imm(a1, 1, 238)
interpret_stm(a1, 32, 1)
interpret_add(a1, 32, 16)
interpret_imm(a1, 1, 101)
interpret_stm(a1, 32, 1)
interpret_add(a1, 32, 16)
interpret_imm(a1, 1, 9)
interpret_stm(a1, 32, 1)
interpret_add(a1, 32, 16)
interpret_imm(a1, 1, 168)
interpret_stm(a1, 32, 1)
interpret_add(a1, 32, 16)
interpret_imm(a1, 1, 33)
interpret_stm(a1, 32, 1)
interpret_add(a1, 32, 16)
interpret_imm(a1, 1, 105)
interpret_stm(a1, 32, 1)
interpret_add(a1, 32, 16)
interpret_imm(a1, 1, 8)
interpret_stm(a1, 32, 1)
interpret_add(a1, 32, 16)


a1_arr[128] += 17
a1_arr[129] += 1
a1_arr[130] += 203
a1_arr[131] += 195
a1_arr[132] += 148
a1_arr[133] += 157
a1_arr[134] += 216
a1_arr[135] += 84
a1_arr[136] += 51
a1_arr[137] += 199
a1_arr[138] += 8
a1_arr[139] += 41

res = ans()
print(res)

io = start()
io.sendafter(b'[+] registers, memory, and system calls.\n', res)
io.interactive()
