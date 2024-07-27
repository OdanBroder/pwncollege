#!/usr/bin/env python3
from pwn import *

context.log_level = "info"
context.binary = elf = ELF("/challenge/babyrev_level16.0", checksec=False)

# libc = ELF('', checksec=False)
libc = elf.libc

gs = """
b *main
b *execute_program
b *execute_program+788
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
a1 = 0x7fffffffddf0
a1_256 = [None] * 7
a1_arr = [None] * 300


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
        error("table_aAbcdsif error!!")


def describe_register(str):
    global aAbcdsif
    if str == 32:
        return aAbcdsif
    elif str == 16:
        return aAbcdsif + 2 * 1
    elif str == 1:
        return aAbcdsif + 2 * 2
    elif str == 8:
        return aAbcdsif + 2 * 3
    elif str == 2:
        return aAbcdsif + 2 * 4
    elif str == 64:
        return aAbcdsif + 2 * 5
    elif str == 4:
        return aAbcdsif + 2 * 6
    elif str:
        return aAbcdsif + 19
    else:
        return aAbcdsif + 2 * 7


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
    if a2 == 32:
        res = a1
        a1_256[0] = a3
        return res
    elif a2 == 16:
        res = a1
        a1_256[1] = a3
        return res
    elif a2 == 1:
        res = a1
        a1_256[2] = a3
        return res
    elif a2 == 8:
        res = a1
        a1_256[3] = a3
        return res
    elif a2 == 2:
        res = a1
        a1_256[4] = a3
        return res
    elif a2 == 64:
        res = a1
        a1_256[5] = a3
        return res
    elif a2 == 4:
        res = a1
        a1_256[6] = a3
        return res
    else:
        error("Error write_register")


def read_register(a1, x):
     
    if x == 32:
            return a1_256[0]
    elif x == 16:
            return a1_256[1]
    elif x == 1:
            return a1_256[2]
    elif x == 8:
            return a1_256[3]
    elif x == 2:
            return a1_256[4]
    elif x == 64:
            return a1_256[5]
    elif x != 4:
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
    v3 = a3
    v4 = describe_register(a2)
    print(
        f"|v4: {hex(v4)} | v3: {hex(v3)} |\nINSTRUCTION SHOW IN CHALLENGE: IMM {chr(table_aAbcdsif(v4))} = {hex(v3)}"
    )
    print("return of interpret_imm: " + hex(write_register(a1, a2, a3)))
    print_arr()


def interpret_stm(a1, a2, a3):
    info("STM")
    v3 = describe_register(a3)
    v4 = describe_register(a2)
    print(
        f"|v4: {hex(v4)} | v3: {hex(v3)} |\nINSTRUCTION SHOW IN CHALLENGE: STM *{chr(table_aAbcdsif(v4))} = {chr(table_aAbcdsif(v3))}"
    )
    v3 = read_register(a1, a3)
    v5 = read_register(a1, a2)
    write_memory(a1, v5, v3)
    print_arr()


def interpret_add(a1, a2, a3):
    info("ADD")
    v3 = describe_register(a3)
    v4 = describe_register(a2)
    print(
        f"|v4: {hex(v4)} | v3: {hex(v3)} |\nINSTRUCTION SHOW IN CHALLENGE: ADD {chr(table_aAbcdsif(v4))}  {chr(table_aAbcdsif(v3))}"
    )
    v3 = read_register(a1, a2)
    v5 = read_register(a1, a3)
    write_register(a1, a2, v3 + v5)
    print_arr()

def interpret_sys(a1, a2, a3): 
    info("SYS")
    v3 = describe_register(a3)
    print(
        f"INSTRUCTION SHOW IN CHALLENGE: SYS {hex(a2)} {chr(table_aAbcdsif(v3))}"
    )
    
     
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
    
    if((a2 & 0x1) != 0):
        print("[s] ... exit")
        exit(a1_256[1])
    
    if(a3):
        v11 = read_register(a1, a3)
        v12 = describe_register(a3)
        print(
            f"[s] ... return value (in register {chr(table_aAbcdsif(v12))}): {hex(v11)}\n"
        )
    
    print_arr()
    return result
 
def interpret_ldm(a1, a2, a3):
    info("LDM")
    v3 = describe_register(a3)
    v4 = describe_register(a2)
    print(
        f"INSTRUCTION SHOW IN CHALLENGE: LDM {chr(table_aAbcdsif(v4))} = *{chr(table_aAbcdsif(v3))}"
    )    
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
    v3 = describe_register(a3)
    v4 = describe_register(a2)
    print(
        f"INSTRUCTION SHOW IN CHALLENGE: CMP {chr(table_aAbcdsif(v4))} {chr(table_aAbcdsif(v3))}"
    )        
    v7 = read_register(a1, a2)
    v8 = read_register(a1, a3)
    a1_256[6] = 0
    if(v7 < v8):
        a1_256[6] |= 2
    if(v7 > v8):
        a1_256[6] |= 4
    if(v7 == v8):
        a1_256[6] |= 0x10
    result = v7
    
    if(v7 != v8):
        result = a1
        a1_256[6] |= 1
    
    if(v7 == 0) and (v8 == 0):
        result = a1
        a1_256[6] |= 8
    
    print_arr()
    return result
     
        
def ans():
    global a1_arr
    res = ""
    for i in range(147, 155):
        res += f"{a1_arr[i]:02x}" 
    return bytes.fromhex(res)

interpret_imm(a1, 16, 115)
interpret_imm(a1, 1, 8)
interpret_imm(a1, 32, 0)
interpret_sys(a1, 32, 32)
interpret_imm(a1, 16, 147)
interpret_imm(a1, 1, 1)
interpret_imm(a1, 32, 178)
interpret_stm(a1, 16, 32)
interpret_add(a1, 16, 1)
interpret_imm(a1, 0x20, 0x8A)
interpret_stm(a1, 16, 32)
interpret_add(a1, 0x10, 1)
interpret_imm(a1, 0x20, 0x6E)
interpret_stm(a1, 16, 32)
interpret_add(a1, 0x10, 1)
interpret_imm(a1, 0x20, 0x5A)
interpret_stm(a1, 16, 32)
interpret_add(a1, 0x10, 1)
interpret_imm(a1, 0x20, 0xAF)
interpret_stm(a1, 16, 32)
interpret_add(a1, 0x10, 1)
interpret_imm(a1, 0x20, 0x33)
interpret_stm(a1, 16, 32)
interpret_add(a1, 0x10, 1)
interpret_imm(a1, 0x20, 0xE9)
interpret_stm(a1, 16, 32)
interpret_add(a1, 0x10, 1)
interpret_imm(a1, 0x20, 0xB9)
interpret_stm(a1, 16, 32)
interpret_add(a1, 0x10, 1)

res = ans()

io = start()
io.sendafter(b'[s] ... read_memory\n', res)
io.interactive()
