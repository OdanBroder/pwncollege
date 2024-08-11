#!/usr/bin/env python3
from pwn import *

context.log_level = "debug"
context.binary = elf = ELF("/challenge/babyrev_level21.0", checksec=False)

libc = elf.libc

gs = """
b *main
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


a1_arr = [None] * 1024
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

yan_code = [] 


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


def write_register_rev(index, value):
    BYTE2 = value
    if index == 0:
        BYTE1 = 8
        return BYTE1, BYTE2
    elif index == 1:
        BYTE1 = 64
        return BYTE1, BYTE2
    elif index == 2:
        BYTE1 = 4
        return BYTE1, BYTE2
    elif index == 3:
        BYTE1 = 1
        return BYTE1, BYTE2
    elif index == 4:
        BYTE1 = 16
        return BYTE1, BYTE2
    elif index == 5:
        BYTE1 = 32
        return BYTE1, BYTE2
    elif index == 6:
        BYTE1 = 2
        return BYTE1, BYTE2
    else:
        error("Error write_register")

def read_register(x):

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

def read_register_rev(index):
    if index == 0:
        return 8
    elif index == 1:
        return 64
    elif index == 2:
        return 4
    elif index == 3:
        return 1
    elif index == 4:
        return 16
    elif index == 5:
        return 32
    elif index != 6:
        error("read_register!!!")
    else:
        return 2

def write_memory(index, value):
    global a1_arr
    res = index
    a1_arr[index + 768] = value
    return res

def read_memory(index):
    global a1_arr
    return a1_arr[index + 768]


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
        
        

def interpret_imm_rev(a1_1024, index, value):
    info("IMM")
    global yan_code
    ret = [0] * 3
    op = 0x80
    #write_register
    a1_1024[index] = value
    
    #Here, value = BYTE2
    BYTE1, BYTE2 = write_register_rev(index, value)
    v2 = describe_register(BYTE1)
    print(f"[s] IMM {chr(table_aAbcdsif(v2))} = {BYTE2}", end=" : ")
    
    a1_1024[5] += 1
    
    ret[0] = op 
    ret[1] = BYTE1
    ret[2] = BYTE2
    yan_code += ret
    return ret
    
def interpret_add_rev(a1_1024, index1, index2):
    info("ADD")    
    global yan_code
    ret = [0] * 3
    op = 0x40
    sum = a1_1024[index1] + a1_1024[index2]
    #write_register
    a1_1024[index1] = sum
    
    #Here, value = BYTE 1 + BYTE2
    BYTE1, SUM = write_register_rev(index1, sum)
    BYTE2 = read_register_rev(index2)
    v2 = describe_register(BYTE2)
    v3 = describe_register(BYTE1)
    print(f"[s] ADD {chr(table_aAbcdsif(v3))}  {chr(table_aAbcdsif(v2))}", end =" : ")
    
    a1_1024[5] += 1
    
    ret[0] = op
    ret[1] = BYTE1
    ret[2] = BYTE2
    yan_code += ret
    return ret  

def interpret_stk_rev(a1_1024, msg, index):
    info("STK")
    global yan_code
    global a1_arr
    ret = [0] * 3
    op = 0x01
    if msg == 'pushing':
        a1_1024[4] += 1
        value = a1_1024[index]
        #write_memory
        write_memory(a1_1024[4], value)
        
        BYTE2 = read_register_rev(index)
        BYTE1 = 0
        v4 =  describe_register(BYTE2)
        print(f"[s] ... pushing {chr(table_aAbcdsif(v4))}")
        
    elif msg == 'popping':
        memory = read_memory(index)
        #write_register
        a1_1024[index] = memory
        
        BYTE1, num = write_register_rev(index, memory)  
        BYTE2 = 0
        v7 = describe_register(BYTE1)
        print(f"[s] ... popping {chr(table_aAbcdsif(v7))}")
        a1_1024[4] -= 1      
    else:
        error("STK error!!!")
    v2 = describe_register(BYTE2)
    v3 = describe_register(BYTE1)
    print(f"[s] STK {chr(table_aAbcdsif(v3))}  {chr(table_aAbcdsif(v2))}")
    
    a1_1024[5] += 1
    
    ret[0] = op
    ret[1] = BYTE1
    ret[2] = BYTE2
    yan_code += ret
    return ret 
        
    

def interpret_stm_rev(a1_1024, index1, index2):
    info("STM")
    global yan_code
    global a1_arr
    ret = [0] * 3
    op = 0x20
    
    value = a1_1024[index2]
    index_store = a1_1024[index1]
    #write_memory
    write_memory(index_store, value)
    
    BYTE1 = read_register_rev(index1)
    BYTE2 = read_register_rev(index2)

    v2 = describe_register(BYTE2)
    v3 = describe_register(BYTE1)
    print(f"[s] STM *{chr(table_aAbcdsif(v3))} = {chr(table_aAbcdsif(v2))}")   
    
    a1_1024[5] += 1
    
    ret[0] = op
    ret[1] = BYTE1
    ret[2] = BYTE2
    yan_code += ret
    return ret 
    


def interpret_ldm_rev(a1_1024, index1, index2):
    info("LDM")
    global yan_code
    global a1_arr
    ret = [0] * 3
    op = 0x04
    
    index_memory = a1_1024[index2]
    memory = read_memory(index_memory)
    a1_1024[index1] = memory
    
    BYTE1, value = write_register_rev(index1, memory)
    BYTE2 = read_register_rev(index2)
    
    v2 = describe_register(BYTE2)
    v3 = describe_register(BYTE1)  
    print(f"[s] LDM {chr(table_aAbcdsif(v3))} = *{chr(table_aAbcdsif(v2))}")
    
    a1_1024[5] += 1
        
    ret[0] = op
    ret[1] = BYTE1
    ret[2] = BYTE2
    yan_code += ret
    return ret 

def interpret_cmp_rev(a1_1024, index1, index2):
    info("CMP")
    global yan_code
    global a1_arr
    ret = [0] * 3
    op = 0x08
    
    v5 = value1 = a1_1024[index1]
    v6 = value2 = a1_1024[index2]
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
        
    BYTE1 = read_register_rev(index1)
    BYTE2 = read_register_rev(index2)
    v2 = describe_register(BYTE2)
    v3 = describe_register(BYTE1)   
    print(f"[s] CMP {chr(table_aAbcdsif(v3))} = {chr(table_aAbcdsif(v2))}")
    
    a1_1024[5] += 1
    
    ret[0] = op
    ret[1] = BYTE1
    ret[2] = BYTE2
    yan_code += ret
    return ret     

def interpret_jmp_rev(a1_1024, msg, index2):
    info("JMP")
    global yan_code
    global a1_arr
    ret = [0] * 3
    op = 0x02
    if msg == 'taken':
        result = a1_1024[index2]
        a1_1024[5] = result
        
        BYTE1 = 0
        BYTE2 = read_register_rev(index2)
        
        print("[j] ... TAKEN")
    elif msg == 'not_taken':
        
        for num in range(1, 255):
            if num & a1_1024[6] == 0:
                BYTE1 = num
                break
        #any value
        BYTE2 = 0
        print("[j] ... NOT TAKEN")
        
    v2 = describe_register(BYTE2)
    v3 = describe_flags(BYTE1)  
    print(f"[j] JMP {table_describe_flags()} {chr(table_aAbcdsif(v2))}") 
    
    a1_1024[5] += 1
    
    ret[0] = op
    ret[1] = BYTE1
    ret[2] = BYTE2
    yan_code += ret
    return ret 
    
#always index = 3 <=> return value on a1[1027]
def interpret_sys_rev(a1_1024, msg, index):
    info("SYS")    
    global yan_code
    global a1_arr
    ret = [0] * 3
    op = 0x10   
    
    BYTE2 = read_register_rev(index)
    
    if msg == 'open':
        BYTE1 = 0x10
        #write_register, v3 = fd = 3 (successful) to a1[1028]
        a1_1024[3] = 3
        
        print("[s] ... open")
    
    elif msg == 'read_memory':
        BYTE1 = 0x8
        
        v7 = 0x01   #the number of char in input
        #write_register
        a1_1024[3] = v7
        
        print("[s] ... read_memory")
    
    elif msg == 'write':
        BYTE1 = 0x1
        
        v9 = 0x01   #the number of char in output
        #write_register
        a1_1024[3] = v9
        
        print("[s] ... write")
    
    elif msg == 'exit':
        BYTE1 = 0x4
    
    else:
        error("Unknow command SYS")
        
    v2 = describe_register(BYTE2)
    print(f"[s] SYS {hex(BYTE1)} {chr(table_aAbcdsif(v2))}")  
        
    if BYTE2 != 0:
        
        v12 = read_register(BYTE2)
        v13 = describe_register(BYTE2)
        print(
            f"[s] ... return value (in register {chr(table_aAbcdsif(v13))}): {hex(v12)}\n"
        )

    ret[0] = op
    ret[1] = BYTE1
    ret[2] = BYTE2
    yan_code += ret
    return ret 
    
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
    print_a1_arr()
    print("\n")


print(interpret_imm_rev(a1_1024, 3, 0x2f))
print(interpret_imm_rev(a1_1024, 2, 0x80))
print(interpret_stm_rev(a1_1024, 2, 3))

print(interpret_imm_rev(a1_1024, 3, 0x66))
print(interpret_imm_rev(a1_1024, 2, 0x81))
print(interpret_stm_rev(a1_1024, 2, 3))

print(interpret_imm_rev(a1_1024, 3, 0x6c))
print(interpret_imm_rev(a1_1024, 2, 0x82))
print(interpret_stm_rev(a1_1024, 2, 3))

print(interpret_imm_rev(a1_1024, 3, 0x61))
print(interpret_imm_rev(a1_1024, 2, 0x83))
print(interpret_stm_rev(a1_1024, 2, 3))

print(interpret_imm_rev(a1_1024, 3, 0x67))
print(interpret_imm_rev(a1_1024, 2, 0x84))
print(interpret_stm_rev(a1_1024, 2, 3))

print(interpret_imm_rev(a1_1024, 3, 0x00))
print(interpret_imm_rev(a1_1024, 2, 0x85))
print(interpret_stm_rev(a1_1024, 2, 3))


print(interpret_imm_rev(a1_1024, 0, 0x80))
print(interpret_imm_rev(a1_1024, 1, 0x00))
print(interpret_sys_rev(a1_1024, 'open', 3))

print(interpret_imm_rev(a1_1024, 0, 0x00))      #a1[1024] = 0
print(interpret_add_rev(a1_1024, 0, 0x03))      #a1[1024] += a1[1027]
print(interpret_imm_rev(a1_1024, 1, 0x50))      #a1[1025] = 0x50
print(interpret_imm_rev(a1_1024, 3, 0x50))      #a1[1026] = 0x50   <length>
print(interpret_sys_rev(a1_1024, 'read_memory', 3))

print(interpret_imm_rev(a1_1024, 0, 0x01))      #a1[1024] = 1
print(interpret_imm_rev(a1_1024, 1, 0x50))      #a1[1025] = 0x50
print(interpret_imm_rev(a1_1024, 3, 0x50))      #a1[1026] = 0x50   <length>
print(interpret_sys_rev(a1_1024, 'write', 3))

print(interpret_sys_rev(a1_1024, 'exit', 3))

print_arr()

print(f"Yancode: {yan_code}")

payload = b''

for byte in yan_code:
    payload += byte.to_bytes(1, 'big')
    

io = start()
sla(b'Please input your yancode: ', payload)
io.interactive()
