#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"
context.binary = elf = ELF("./babyrev_level21.0", checksec=False)

libc = elf.libc

gs = """
b *main
b *interpret_sys+491
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


dest = 0x7FFFFFFFDAF0
a1 = dest
dest_sub_0x20 = dest - 0x20
vm_mem = 0x555555559320
vm_code = 0x555555559020
vm_code_length = 0x2B2


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

index_flag = 11
flag = [0] * 12
index_loop = 0


 
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


def describe_register(str):
    global aAbcdsif
    if str == 8:
        return aAbcdsif
    elif str == 64:
        return aAbcdsif + 2 * 1
    elif str == 4:
        return aAbcdsif + 2 * 2
    elif str == 1:
        return aAbcdsif + 2 * 3
    elif str == 16:
        return aAbcdsif + 2 * 4
    elif str == 32:
        return aAbcdsif + 2 * 5
    elif str == 2:
        return aAbcdsif + 2 * 6
    elif str:
        return aAbcdsif + 19
    else:
        return aAbcdsif + 2 * 7


def write_register(a1, a2, a3):
    global a1_1024
    if a2 == 8:
        res = a1
        a1_1024[0] = a3
        return res
    elif a2 == 64:
        res = a1
        a1_1024[1] = a3
        return res
    elif a2 == 4:
        res = a1
        a1_1024[2] = a3
        return res
    elif a2 == 1:
        res = a1
        a1_1024[3] = a3
        return res
    elif a2 == 16:
        res = a1
        a1_1024[4] = a3
        return res
    elif a2 == 32:
        res = a1
        a1_1024[5] = a3
        return res
    elif a2 == 2:
        res = a1
        a1_1024[6] = a3
        return res
    else:
        error("Error write_register")


def read_register(a1, x):

    if x == 8:
        return a1_1024[0]
    elif x == 64:
        return a1_1024[1]
    elif x == 4:
        return a1_1024[2]
    elif x == 1:
        return a1_1024[3]
    elif x == 16:
        return a1_1024[4]
    elif x == 32:
        return a1_1024[5]
    elif x != 2:
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
    
    if a1 & 0x10 != 0:
        flag_description_arr[0] = 76
        v2 = 1
    
    if a1 & 0x2 != 0:
        flag_description_arr[v2] = 71
        v2 = v2 + 1
    
    if a1 & 0x8 != 0:
        flag_description_arr[v2] = 69
        v2 = v2 + 1
    
    if a1 & 0x1 != 0:
        flag_description_arr[v2] = 78
        v2 = v2 + 1
    
    if a1 & 0x4 != 0:
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
    v2 = describe_register(a2_hex_arr[1])
    print(f"IMM {chr(table_aAbcdsif(v2))} = {hex(a2_hex_arr[2])}")
    write_register(a1, a2_hex_arr[1], a2_hex_arr[2])
    


def interpret_add(a1, a2_hex_arr):
    info("ADD")
    v2 = describe_register(a2_hex_arr[2])
    v3 = describe_register(a2_hex_arr[1])
    print(f"[s] ADD {chr(table_aAbcdsif(v3))}  {chr(table_aAbcdsif(v2))}")
    v2 = read_register(a1, a2_hex_arr[1])
    v4 = read_register(a1, a2_hex_arr[2])
    #problem happens when v2 + v4 > 0x100
    if v2 + v4 > 0x100:
        sum = v2 + v4 - 0x100
    else:
        sum = v2 + v4
    write_register(a1, a2_hex_arr[1], sum)
    

def interpret_stk(a1, a2_hex_arr):
    info("STK")
    global a1_1024
    v2 = describe_register(a2_hex_arr[2])
    v3 = describe_register(a2_hex_arr[1])
    print(f"[s] STK {chr(table_aAbcdsif(v3))}  {chr(table_aAbcdsif(v2))}")
    
    if a2_hex_arr[2]:
        v4 =  describe_register(a2_hex_arr[2])
        print(f"[s] ... pushing {chr(table_aAbcdsif(v4))}")
        a1_1024[4] += 1 
        v5 = read_register(a1, a2_hex_arr[2])
        write_memory(a1, a1_1024[4], v5)
        
    result = a2_hex_arr[2]
    
    if a2_hex_arr[1]:
        v7 = describe_register(a2_hex_arr[1])
        print(f"[s] ... popping {chr(table_aAbcdsif(v7))}")
        memory = read_memory(a1, a1_1024[4])
        write_register(a1, a2_hex_arr[1], memory)
        result = a1
        a1_1024[4] -= 1
    
    return result

def interpret_stm(a1, a2_hex_arr):
    info("STM")
    v2 = describe_register(a2_hex_arr[2])
    v3 = describe_register(a2_hex_arr[1])
    print(f"[s] STM *{chr(table_aAbcdsif(v3))} = {chr(table_aAbcdsif(v2))}")
    v2 = read_register(a1, a2_hex_arr[2])
    v4 = read_register(a1, a2_hex_arr[1])
    write_memory(a1, v4, v2)


def interpret_ldm(a1, a2_hex_arr):
    info("LDM")
    v2 = describe_register(a2_hex_arr[2])
    v3 = describe_register(a2_hex_arr[1])  
    print(f"[s] LDM {chr(table_aAbcdsif(v3))} = *{chr(table_aAbcdsif(v2))}")
    v4 = read_register(a1, a2_hex_arr[2])
    memory = read_memory(a1, v4)
    #info("v4 @ " + hex(v4))
    #info("memory @ " + hex(memory))
    write_register(a1, a2_hex_arr[1], memory)
    

def interpret_cmp(a1, a2_hex_arr):
    info("CMP")
    global a1_1024
    global index_flag
    global index_loop
    global flag
    
    v2 = describe_register(a2_hex_arr[2])
    v3 = describe_register(a2_hex_arr[1])   
    print(f"[s] CMP {chr(table_aAbcdsif(v3))} = {chr(table_aAbcdsif(v2))}")
    
    v5 = read_register(a1, a2_hex_arr[1])
    v6 = read_register(a1, a2_hex_arr[2])
    a1_1024[6] = 0
    if v5 < v6:
        a1_1024[6] |= 0x10
        
    if v5 > v6:
        a1_1024[6] |= 0x2
    
    if v5 == v6:
        a1_1024[6] |= 0x8
    
    result = v5

    if v5 != v6:
        result = a1
        a1_1024[6] |= 0x1
    
    if v5 == 0 and v6 == 0:
        result = a1
        a1_1024[6] |= 0x4
    
    
    return result       

def interpret_jmp(a1, a2_hex_arr):
    info("JMP")
    global a1_1024  
    v2 = describe_register(a2_hex_arr[2])
    v3 = describe_flags(a2_hex_arr[1])  
    print(f"[j] JMP {table_describe_flags()} {chr(table_aAbcdsif(v2))}")   
    
    if a2_hex_arr[1] != 0  and a2_hex_arr[1] & a1_1024[6] == 0:
        
        return print("[j] ... NOT TAKEN")
    
    print("[j] ... TAKEN")
    
    result = read_register(a1, a2_hex_arr[2])
    a1_1024[5] = result
    
    return result


    
def interpret_sys(a1, a2_hex_arr):
    global flag
    global index_flag
    info("SYS")    
    
    v2 = describe_register(a2_hex_arr[2])
    print(f"[s] SYS {hex(a2_hex_arr[1])} {chr(table_aAbcdsif(v2))}")
    
    a2_and_option = a2_hex_arr[1]
    
    if((a2_and_option & 0x8) != 0):
        print("[s] ... read_memory")
        v6 = a1_1024[2]
        if (256 - a1_1024[1] <= v6):
            v6 = -a1_1024[1]
            
        for i in range (len(flag)):
            a1_arr[a1_1024[1] + i + 768] = flag[i]
        
        write_register(a1, a2_hex_arr[1], len(flag))
    
    if((a2_and_option & 0x1) != 0):
        print("[s] ... write")
        v8 = a1_1024[2]
        if(256 - a1_1024[1] <= v8):
            v8 = - a1_1024[1]
        print(a1_arr[a1_1024[1] + 768])
        write_register(a1, a2_hex_arr[1], 1)
    
    result = a2_hex_arr[1]
    
    if((a2_and_option & 0x4) != 0):
        print("[s] ... exit")
        return 0xdeadbeef
    
    if(a2_hex_arr[2]):
        v12 = read_register(a1, a2_hex_arr[2])
        v13 = describe_register(a2_hex_arr[2])
        print(
            f"[s] ... return value (in register {chr(table_aAbcdsif(v13))}): {hex(v12)}\n"
        )
        return 
    
    
    return result  

def interpret_instruction(a1, a2):
    print(
        f"[V] a:{hex(a1_1024[0])} b:{hex(a1_1024[1])} c:{hex(a1_1024[2])} d:{hex(a1_1024[3])} s:{hex(a1_1024[4])} i:{hex(a1_1024[5])} f:{hex(a1_1024[6])}"
    )
    a2_hex_str = f"{a2:02x}".zfill(6)

    a2_hex_arr = [None] * 3
    op = a2_hex_arr[0] = int(a2_hex_str[4:6], 16)
    arg2 = a2_hex_arr[1] = int(a2_hex_str[2:4], 16)
    arg1 = a2_hex_arr[2] = int(a2_hex_str[0:2], 16)

    print(f"[I] op:{hex(op)} arg1:{hex(arg1)} arg2:{hex(arg2)}")

    if op & 0x80 != 0:
        interpret_imm(a1, a2_hex_arr)
        
    if op & 0x40 != 0:
        interpret_add(a1, a2_hex_arr)
        
    if op & 0x80 != 0:
        interpret_stk(a1, a2_hex_arr)  

    if op & 0x1 != 0:
        interpret_stm(a1, a2_hex_arr)          
    
    if op & 0x20 != 0:
        interpret_ldm(a1, a2_hex_arr)   

    if op & 0x8 != 0:
        interpret_cmp(a1, a2_hex_arr) 
  
    if op & 0x2 != 0:
        interpret_jmp(a1, a2_hex_arr)   
        
    result = op & 0x10
    
    if op & 0x10 != 0:
        return interpret_sys(a1, a2_hex_arr)
    
    return result

def interpreter_loop(a1):
    global a1_arr
    global a1_1024
    global index_loop
    print("[+] Starting interpreter loop! Good luck!")
    while True:
        v1 = a1_1024[5]
        a1_1024[5] = v1 + 1
        x = a1_arr[3 * v1] | (a1_arr[3 * v1 + 1] << 8)
        y = (a1_arr[3 * v1 + 2] << 16)
        check = interpret_instruction(a1, x | y)
        if check == 0xdeadbeef:
            return check
        if index_flag == -1:
            return flag


