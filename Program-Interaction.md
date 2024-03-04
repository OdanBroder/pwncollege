# 1. Level 1:
`./embryoio_level1`.
# 2. Level 2:
-It is clear that password over stdin is wetfgxbn.
![image](https://hackmd.io/_uploads/Skl7HL9iT.png)
# 3. Level 3:
![image](https://hackmd.io/_uploads/rJn8NU9j6.png)
-Look at the instruction, that require argv[1] is ytiykrycyk.
`./embryoio_level3 ytiykrycyk` .
# 4. Level 4:
![image](https://hackmd.io/_uploads/B1RiBLco6.png)
-You need to create environment variable which key is tqtikv and value is yglummhigy.
`export tqtikv=yglummhigy`
# 5. Level 5:
![image](https://hackmd.io/_uploads/rkJMPUcop.png)
-It require that create file contain hhmbyljb.
```
echo "hhmbyljb" > /tmp/anspoc
./embryoio_level5 < anspoc
```
# 6. Level 6:
![image](https://hackmd.io/_uploads/BkkJd93oa.png)
```
/challenge/embryoio_level6 > /tmp/enhwpg
cat /tmp/enhwpg
```
# 7. Level 7:
![image](https://hackmd.io/_uploads/HJoF9c3iT.png)
`
# 8. Level 8:
![image](https://hackmd.io/_uploads/SJQW3c2j6.png)
-You only create file myscript.sh contain
```
#!/bin/bash
/challenge/embryoio_level8
```
`bash myscript.sh`
# 9. Level 9:
![image](https://hackmd.io/_uploads/SywHT9hsa.png)
-It similar to level 8, but the difference is checking password(stdin) after run file script.
# 10. Level 10:
![image](https://hackmd.io/_uploads/SJfX092ip.png)
```
#!/bin/bash
/challenge/embryoio_level10 kvngcjhglv
```
# 11. Level 11:
![image](https://hackmd.io/_uploads/HJvNx3x2T.png)
```
#!/bin/bash
export caogqf=ssgxjrocni
/challenge/embryoio_level11
```
# 12. Level 12:
![image](https://hackmd.io/_uploads/r1pie2gha.png)
```
#!/bin/bash
echo "ndalulxw" > /tmp/bnitsh
/challenge/embryoio_level12 < /tmp/bnitsh
```
# 13. Level 13:
![image](https://hackmd.io/_uploads/H1ucf3gh6.png)
```
#!/bin/bash
/challenge/embryoio_level13 > /tmp/umcqpn
cat /tmp/umcqpn
```
# 14. Level 14:
![image](https://hackmd.io/_uploads/ByrEX3eh6.png)
```
#!/bin/bash
env -i /challenge/embryoio_level14
```
# 15. Level 15:
![image](https://hackmd.io/_uploads/HkugVng2T.png)
```
ipython
from pwn import *
r = process(/challenge/embryoio_level15)
r.interactive()
```
-Or you can use subprocess library
```
ipython
import subprocess
subprocess.run(["/challenge/embryoio_level15"])
```
# 16. Level 16:
![image](https://hackmd.io/_uploads/HyCteag2a.png)

-It is similar to level 15, but the program will check your stdin (password).
# 17. Level 17:
![image](https://hackmd.io/_uploads/rJgBZ6ghp.png)
```
ipython
from pwn import *
r = process(['challenge/embryoio_level17','onesezqejh'])
r.interactive()
```

```
ipython
import subprocess
subprocess.run(['challenge/embryoio_level17','onesezqejh'])
```
# 18. Level 18:
![image](https://hackmd.io/_uploads/rJusf6e3T.png)
```
ipython
from pwn import *
r = process('/challenge/embryoio_level18', env = {'eqobqe' : 'nhrrbcevao' })
r.interactive()
```

```
ipython
import subprocess
subprocess.run("/challenge/embryoio_level18",env ={'eqobqe' : 'nhrrbcevao'})
```
# 19. Level 19:
![image](https://hackmd.io/_uploads/rJHEVal3p.png)
```
ipython
from pwn import *
import os

with open("/tmp/ksxulp", 'w') as file:
    file.write("unacqfbu")

fd = os.open("/tmp/ksxulp", os.O_RDONLY)

r = process('/challenge/embryoio_level19', stdin=fd)
r.interactive()
```

```
ipython
import subprocess 
o = open('/tmp/ksxulp', 'w+')
o.write("unacqfbu")
o.close()
o = open('/tmp/ksxulp')
subprocess.Popen("/challenge/embryoio_level19", stdin=o)
```
# 20. Level 20:
![image](https://hackmd.io/_uploads/SkjzL6ehT.png)
```
from pwn import *
import os

fd = os.open("/tmp/wxngwq", os.O_WRONLY | os.O_CREAT)

p = process('/challenge/embryoio_level20', stdout=fd)

with open("/tmp/wxngwq", 'r') as file:
	print(file.read())
```

```
ipython
import subprocess
o = open('/tmp/wxngwq', 'w+')
subprocess.Popen("/challenge/embryoio_level20", stdout=o)
o.close()
o = open('/tmp/wxngwq', 'r')
print(o.read())
```
# 21. Level 21:
![image](https://hackmd.io/_uploads/H1yYL0W2a.png)
```
from pwn import *
import os

p = process('/challenge/embryoio_level21', env={})

p.interactive()
```

```
ipython
import subprocess
subprocess.run("/challenge/embryoio_level18",env ={})
```
# 22. Level 22:
![image](https://hackmd.io/_uploads/Hy0h8R-n6.png)
```
from pwn import *

p = process('/challenge/embryoio_level22')
p.interactive()
```
# 23. Level 23:
![image](https://hackmd.io/_uploads/r1_Ec0bnp.png)
-It is similar to level 22, but the program will check your stdin (password).
# 24. Level 24:
![image](https://hackmd.io/_uploads/HkZRcAbnp.png)
```
from pwn import *

p = process(['/challenge/embryoio_level23','hvcwkmqhxb'])
p.interactive()
```
# 25. Level 25:
![image](https://hackmd.io/_uploads/Hkr7iAb2T.png)
```
from pwn import *

p = process('/challenge/embryoio_level25', env ={'fvrsji' : 'zcnrdckmtg'})
p.interactive()
```
# 26. Level 26:
![image](https://hackmd.io/_uploads/Sy-120b2p.png)
```
from pwn import *
import os
with open("/tmp/sjfilu", "w") as file: file.write("ptawmldj")
fd = os.open("/tmp/sjfilu", os.O_RDONLY)
r = process('/challenge/embryoio_level26', stdin = fd)
r.interactive()
```
# 27. Level 27:
![image](https://hackmd.io/_uploads/Hy37pRZ26.png)
```
from pwn import *
import os
fd = os.open("/tmp/fnnofu",os.O_WRONLY | os.O_CREAT)
r = process('/challenge/embryoio_level26', stdout = fd)
with open("/tmp/fnnofu", 'r') as file: print(file.read())
```
# 28. Level 28:
![image](https://hackmd.io/_uploads/r1ai1yz3a.png)
```
from pwn import *

r = process('/challenge/embryoio_level28', env = {})
r.interactive()
```
# 29. Level 29:
![image](https://hackmd.io/_uploads/BkjXxyMhp.png)
```
#include <stdio.h>
#include <stdlib.h>

void pwncollege () {

}

int main () {
	const char filename[100] = "/challenge/embryoio_level29";

	pid_t cpid;

	if (fork() == 0) {
		execve(filename, NULL, NULL);
		exit(0);
	}
	else {
		cpid = wait(NULL);
	}

	return 0;
}
```
# 30. Level 30:
![image](https://hackmd.io/_uploads/rk6jikG2p.png)
-It is similar to level 29, but the program will check your stdin (password).
# 31. Level 31:
![image](https://hackmd.io/_uploads/BkhWcdQnT.png)
```
#include <stdio.h>
#include <stdlib.h>

void pwncollege () {

}

int main () {
	const char filename[100] = "/challenge/embryoio_level31";

	pid_t cpid;
    char* input[] = {filename,"nlhrekavwx", NULL};
	if (fork() == 0) {
		execve(filename, input, NULL);
		exit(0);
	}
	else {
		cpid = wait(NULL);
	}

	return 0;
}
```
# 32. Level 32:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : iypurm:injynbnrmg
```
#include<stdio.h>
#include<unistd.h>

void pwncollege(){}

int main()
{
        const char filename[100] = "/challenge/embryoio_level32";
        char *input[] = {filename, NULL, NULL};
        char* envp[] = {"iypurm=injynbnrmg", NULL};
        if(fork() == 0){
                execve(filename, input, envp);
        }else{
                wait(NULL);
        }
}
```
# 33. Level 33:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will check that input is redirected from a specific file path : /tmp/jhaawx
> - the challenge will check for a hardcoded password over stdin : cdaaudng
```
#include<stdio.h>
#include<unistd.h>
#include<errno.h>
#include<fcntl.h>


void pwncollege(){}

int main()
{
        const char filename[100] = "/challenge/embryoio_level33";
        char* password = "cdaaudng";
        char* input[] = {filename, " < /tmp/jhaawx", NULL};
        pid_t cpid;
        if(fork() == 0){
                close(0);
                int fd = open("/tmp/jhaawx", O_RDONLY | O_WRONLY);
                if(fd == -1){
                        printf("Error number:%d\n", errno);
                        perror("Program");
                }
                size_t sz = write(fd, password, strlen(password));
                execve(filename, input, NULL);
        }else{
                wait(NULL);
        }
}
```
-This is my first code, and there are some wrong when checker.py works:
> Traceback (most recent call last):
>   File "/challenge/checker.py", line 516, in <module>
>     do_checks(_args)
>   File "/challenge/checker.py", line 401, in do_checks
>     check_password(args.password)
>   File "/challenge/checker.py", line 263, in check_password
>     response = input().strip()
> OSError: [Errno 9] Bad file descriptor

-I don't know exactly it means, so I try to write password outside.
```
#include<stdio.h>
#include<unistd.h>
#include<errno.h>
#include<fcntl.h>


void pwncollege(){}

int main()
{
        const char filename[100] = "/challenge/embryoio_level33";
//      char* password = "cdaaudng";
        char* input[] = {filename, " < /tmp/jhaawx", NULL};
        pid_t cpid;
        if(fork() == 0){
                int fd = open("/tmp/jhaawx", O_RDONLY);
                if(fd == -1){
                        printf("Error number:%d\n", errno);
                        perror("Program");
                }
//              size_t sz = write(fd, password, strlen(password));
                execve(filename, input, NULL);
        }else{
                wait(NULL);
        }
}
```
-Fortunately, it works correctly. 
# 34. Level 34:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will check that output is redirected to a specific file path : /tmp/fhyqsa

-In this level, I try to write my code similar to level 33:
```
#include<stdio.h>
#include<unistd.h>
#include<errno.h>
#include<fcntl.h>


void pwncollege(){}

int main()
{
        const char filename[100] = "/challenge/embryoio_level34";
        char* input[] = {filename, " > /tmp/fhyqsa ", NULL};
        pid_t cpid;
        if(fork() == 0){
                close(0);
                int fd = open("/tmp/fhyqsa", O_RDONLY | O_WRONLY);
                if(fd == -1){
                        printf("Error number:%d\n", errno);
                        perror("Program");
                }
                execve(filename, input, NULL);
        }else{
                wait(NULL);
        }
}
```
-Unfortunately, it don't work because I don really restricted file to /tmp/fhyqsa.
-See the dup() fucntion work in https://stackoverflow.com/questions/7861611/can-someone-explain-what-dup-in-c-does. 
```
#include<stdio.h>
#include<unistd.h>
#include<error.h>
#include<fcntl.h>

void pwncollege(){}

int main()
{
        const char filename[100] = "/challenge/embryoio_level34";
        pid_t cpid;
        if(fork() == 0){
                int fd = open("/tmp/fhyqsa", O_RDONLY | O_WRONLY | O_CREAT);
                if(fd == -1){
                        perror("Error writting");
                }
                close(1);
                dup(fd);
                close(fd);
                execve(filename, NULL, NULL);
        }else{
                wait(NULL);
        }
        return 0;
}
```
-Or it will be quick to use dup2():
```
#include<stdio.h>
#include<unistd.h>
#include<error.h>
#include<fcntl.h>

void pwncollege(){}

int main()
{
        const char filename[100] = "/challenge/embryoio_level34";
        pid_t cpid;
        if(fork() == 0){
                int fd = open("/tmp/fhyqsa", O_RDONLY | O_WRONLY | O_CREAT);
                if(fd == -1){
                        perror("Error writting");
                }
                dup2(fd, 1);
                close(fd);
                execve(filename, NULL, NULL);
        }else{
                wait(NULL);
        }
        return 0;
}
```
-After this level, You can use dup to solve problem in level 33. Furhtermore, I notice that my script in level 33 look like trick =)).
# 35. Level 35:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)

-It is simple that you run file script without setting envrionment variable, so script in level 29 will be work.
# 36. Level 36:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : bash
> - the challenge checks for a specific process at the other end of stdout : cat
    
`/challenge/embryoio_level36 | cat`
# 37. Level 37:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : bash
> - the challenge checks for a specific process at the other end of stdout : grep

`/challenge/embryoio_level37 | grep pwn`
# 38. Level 38:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : bash
> - the challenge checks for a specific process at the other end of stdout : sed
    
`/challenge/embryoio_level38 | sed -n "s/pwn/pwn/p"`
# 39. Level 39:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : bash
> - the challenge checks for a specific process at the other end of stdout : rev

`/challenge/embryoio_level39 | rev | rev`
# 40. Level 40:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : bash
> - the challenge checks for a specific process at the other end of stdin : cat
> - the challenge will check for a hardcoded password over stdin : hpvhikuz
    
-It is easy to execute command `cat | /challenge/embryoio_level40` and input your password.
# 41. Level 41:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : bash
> - the challenge checks for a specific process at the other end of stdin : rev
> - the challenge will check for a hardcoded password over stdin : xzgyyfgq

-`rev | /challenge/embryoio_level41` and input your password.
# 42. Level 42:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge checks for a specific process at the other end of stdout : cat

```
#!/bin/bash

/challenge/embryoio_level42 | cat
```
# 43. Level 43:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge checks for a specific process at the other end of stdout : grep
    
```
#!/bin/bash

/challenge/embryoio_level43 | grep "pwn"
```
# 44. Level 44:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge checks for a specific process at the other end of stdout : sed
    
```
#!/bin/bash

/challenge/embryoio_level44 | sed -n "s/pwn/pwn/p"
```
# 45. Level 45:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge checks for a specific process at the other end of stdout : rev
    
```
#!/bin/bash

/challenge/embryoio_level45 | rev | rev
```
# 46. Level 46:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge checks for a specific process at the other end of stdin : cat
> - the challenge will check for a hardcoded password over stdin : mneddptd
    
```
#!/bin/bash

cat | /challenge/embryoio_level46
```
-Then, put your password.
# 47. Level 47:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge checks for a specific process at the other end of stdin : rev
> - the challenge will check for a hardcoded password over stdin : icgtasos
    
```
#!/bin/bash

rev | /challenge/embryoio_level47
```
-Then, put your password.
# 48. Level 48:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : ipython
> - the challenge checks for a specific process at the other end of stdout : cat

```
ipython
import subprocess
p = subprocess.Popen('cat', shell=False, stdin=subprocess.PIPE)
subprocess.call('/challenge/embryoio_level48', shell=False, stdout=p.stdin)
```
# 49. Level 49:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : ipython
> - the challenge checks for a specific process at the other end of stdout : grep
    
```
ipython
import subprocess
p = subprocess.Popen(['grep','pwn'], shell=False, stdin=subprocess.PIPE)
subprocess.call('/challenge/embryoio_level49', shell=False, stdout=p.stdin)
```
# 50. Level 50:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : ipython
> - the challenge checks for a specific process at the other end of stdout : sed
    
```
ipython
p = subprocess.Popen(['sed', "-n", "s/pwn/pwn/p"], shell=False, stdin=subprocess.PIPE)
subprocess.run("/challenge/embryoio_level50", shell=False, stdout=p.stdin)
```
# 51. Level 51:
```
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : ipython
- the challenge checks for a specific process at the other end of stdout : rev
```

```
ipython
import subprocess
q = subprocess.Popen(["rev"], shell=False, stdin=subprocess.PIPE)
p = subprocess.Popen(['rev'], shell=False, stdin=subprocess.PIPE, stdout=q.stdin)
subprocess.run("/challenge/embryoio_level51", shell=False, stdout=p.stdin)
```
-After you write this code, quit and receive flag.
# 52. Level 52:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : ipython
> - the challenge checks for a specific process at the other end of stdin : cat
> - the challenge will check for a hardcoded password over stdin : hybsgpbp

```
ipython
import subprocess
p2 = subprocess.Popen("cat", shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
p1 = subprocess.Popen(["echo", "hybsgpbp"], shell=False, stdout=p2.stdin)
p3 = subprocess.Popen("/challenge/embryoio_level52", shell=False, stdin=p2.stdout)
```
# 53. Level 53:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : ipython
> - the challenge checks for a specific process at the other end of stdin : rev
> - the challenge will check for a hardcoded password over stdin : yirvlcfg
    
-First, I try to write code similar to this in level 52. However, it seem that your stin is reversed:
`[FAIL]    You entered the wrong password (gfclvriy instead of yirvlcfg).`
-Therefore, I have make two process of rev.
```
ipython
import subprocess
p3 = subprocess.Popen("rev", shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
p2 = subprocess.Popen("rev", shell=False, stdin=subprocess.PIPE, stdout=p3.stdin)
p1 = subprocess.Popen(["echo", "yirvlcfg"], shell=False, stdout=p2.stdin)
p4 = subprocess.Popen("/challenge/embryoio_level53", shell=False, stdin=p3.stdout)
```
# 54. Level 54:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge checks for a specific process at the other end of stdout : cat

```
from pwn import *
p = process('cat')
q = process('/challenge/embryoio_level54', stdout=p.stdin)
p.interactive()
```
# 55. Level 55:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge checks for a specific process at the other end of stdout : grep
```
from pwn import *
p = process(['grep','pwn'])
q = process('/challenge/embryoio_level55', stdout=p.stdin)
p.interactive()
```
# 56. Level 56:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge checks for a specific process at the other end of stdout : sed
```
from pwn import *
p = process(['sed', '-n', 's/pwn/pwn/p'])
q = process('/challenge/embryoio_level56', stdout=p.stdin)
p.interactive()
```
# 57. Level 57:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge checks for a specific process at the other end of stdout : rev
    
```
from pwn import *
p = process(['rev'])
q = process('/challenge/embryoio_level57', stdout=p.stdin)
p.interactive()
```
-After that, you need to reverse string.
# 58. Level 58:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge checks for a specific process at the other end of stdin : cat
> - the challenge will check for a hardcoded password over stdin : nqiinpbk
```

from pwn import *
p = process('cat', stdout=PIPE)
p.sendline(b'nqiinpbk')
q = process('/challenge/embryoio_level58', stdin=p.stdout)
q.interactive()
```
# 59. Level 59:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge checks for a specific process at the other end of stdin : rev
> - the challenge will check for a hardcoded password over stdin : ourlsuaz
```
from time import sleep
import subprocess
import os
p3 = subprocess.Popen("rev", shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
p2 = subprocess.Popen("rev", shell=False, stdin=subprocess.PIPE, stdout=p3.stdin)
p1 = subprocess.Popen(["echo", "ourlsuaz"], shell=False, stdout=p2.stdin)
p4 = subprocess.Popen("/challenge/embryoio_level59", shell=False, stdin=p3.stdout)
p4.wait(timeout=4)
```
# 60. Level 60:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge checks for a specific process at the other end of stdout : cat
    
```
#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>

void pwncollege(){
    int fork1 = fork();
    if(fork1 == 0){
        char* filename = "/challenge/embryoio_level60";
        char* binary = "/usr/bin/cat";
        char* path = "/usr/bin/cat";
        pid_t cpid;
        int pipe_fds[2];
        pipe(pipe_fds);
        int fork2 = fork();
        if(fork2 >  0){
            dup2(pipe_fds[1], 1);
            close(pipe_fds[0]);
            execve(filename, NULL, NULL);
        }else if(fork2 == 0){
            dup2(pipe_fds[0], 0);
            close(pipe_fds[1]);
            execl(binary, path, NULL);
        }
    }else{
        waitpid(fork1, NULL, 0);
    }
}
int main()
{
    pwncollege();
    return 0;
}
    
```
# 61. Level 61:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge checks for a specific process at the other end of stdout : grep
```
#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>

void pwncollege(){
    int fork1 = fork();
    if(fork1 == 0){
        char* filename = "/challenge/embryoio_level61";
        char* binary = "/usr/bin/grep";
        char* path = "/usr/bin/grep";
        char* input = "pwn";
        pid_t cpid;
        int pipe_fds[2];
        pipe(pipe_fds);
        int fork2 = fork();
        if(fork2 >  0){
            dup2(pipe_fds[1], 1);
            close(pipe_fds[0]);
            execve(filename, NULL, NULL);
        }else if(fork2 == 0){
            dup2(pipe_fds[0], 0);
            close(pipe_fds[1]);
            execl(binary, path, input, NULL);
        }
    }else{
        waitpid(fork1, NULL, 0);
    }
}
int main()
{
    pwncollege();
    return 0;
}
```
# 62. Level 62:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge checks for a specific process at the other end of stdout : sed
    
```
#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>

void pwncollege(){
    int fork1 = fork();
    if(fork1 == 0){
        char* filename = "/challenge/embryoio_level62";
        char* binary = "/usr/bin/sed";
        char* path = "/usr/bin/sed";
        char* input = "s/pwn/pwn/p";
        pid_t cpid;
        int pipe_fds[2];
        pipe(pipe_fds);
        int fork2 = fork();
        if(fork2 >  0){
            dup2(pipe_fds[1], 1);
            close(pipe_fds[0]);
            execve(filename, NULL, NULL);
        }else if(fork2 == 0){
            dup2(pipe_fds[0], 0);
            close(pipe_fds[1]);
            execl(binary, path, "-n", input, NULL);
        }
    }else{
        waitpid(fork1, NULL, 0);
    }
}
int main()
{
    pwncollege();
    return 0;
}
```
# 63. Level 63:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge checks for a specific process at the other end of stdout : rev

```
#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>

void pwncollege(){
    int fork1 = fork();
    if(fork1 == 0){
        char* filename = "/challenge/embryoio_level63";
        char* binary = "/usr/bin/rev";
        char* path = "/usr/bin/rev";
        pid_t cpid;
        int pipe_fds[2];
        pipe(pipe_fds);
        int fork2 = fork();
        if(fork2 >  0){
            dup2(pipe_fds[1], 1);
            close(pipe_fds[0]);
            execve(filename, NULL, NULL);
        }else if(fork2 == 0){
            dup2(pipe_fds[0], 0);
            close(pipe_fds[1]);
            execl(binary, path, NULL);
        }
    }else{
        waitpid(fork1, NULL, 0);
    }
}
int main()
{
    pwncollege();
    return 0;
}
```    
# 63. Level 64:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge checks for a specific process at the other end of stdin : cat
> - the challenge will check for a hardcoded password over stdin : ebqtcdsu

```
#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>

void pwncollege(){
    int fork1 = fork();
    if(fork1 == 0){
        char* filename = "/challenge/embryoio_level64";
        char* binary = "/usr/bin/cat";
        char* path = "/usr/bin/cat";
        pid_t cpid;
        int pipe_fds[2];
        pipe(pipe_fds);
        int fork2 = fork();
        if(fork2 >  0){
            dup2(pipe_fds[0], 0);
            close(pipe_fds[1]);
            execve(filename, NULL, NULL);
        }else if(fork2 == 0){
            dup2(pipe_fds[1], 1);
            close(pipe_fds[0]);
            execl(binary, path, NULL);
        }
    }else{
        waitpid(fork1, NULL, 0);
    }
}
int main()
{
    pwncollege();
    return 0;
}
```
# 65. Level 65:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge checks for a specific process at the other end of stdin : rev
> - the challenge will check for a hardcoded password over stdin : bffjthhw
    
```
#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>

void pwncollege(){
    int fork1 = fork();
    if(fork1 == 0){
        char* filename = "/challenge/embryoio_level65";
        char* binary = "/usr/bin/rev";
        char* path = "/usr/bin/rev";
        pid_t cpid;
        int pipe_fds[2];
        pipe(pipe_fds);
        int fork2 = fork();
        if(fork2 >  0){
            dup2(pipe_fds[0], 0);
            close(pipe_fds[1]);
            execve(filename, NULL, NULL);
        }else if(fork2 == 0){
            dup2(pipe_fds[1], 1);
            close(pipe_fds[0]);
            execl(binary, path, NULL);
        }
    }else{
        waitpid(fork1, NULL, 0);
    }
}
int main()
{
    pwncollege();
    return 0;
}
```
# 66. Level 66:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : find

    ` find . -exec /challenge/embryoio_level66 \;`
# 67. Level 67:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : find
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 1:ivmffonqxf

`find . -exec /challenge/embryoio_level67 ivmffonqxf \;`

# 68. Level 68:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 307:oychnztsoh
    
-See solution here: https://unix.stackexchange.com/questions/188658/writing-a-character-n-times-using-the-printf-command

```
#!/bin/sh
/challenge/embryoio_level68 `printf 'oychnztsoh%0.s ' {1..307}`
```
# 70. Level 70:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)
> - the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : 296:xmnmhojqjt

-I write code C and compile to file binary with name is bash
-After that, I pass command `./bash /tmp/script.sh`. It is trick =))).

```
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>

void pwncollege(char* argv[], char* env[]){
    char* aa[] = {"296=xmnmhojqjt", NULL};
    execve("/challenge/embryoio_level70", argv, aa);
    return;
}

int main(int argc, char* argv[], char* env)
{
    pid_t cpid;
    cpid = fork();
    if(cpid < 0){
        printf("error\n");
    }else if(cpid == 0){
        pwncollege(argv, env);
    }else{
        wait(NULL);
    }
    return 0;
}
```
# 71. Level 71:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 295:jogxqfpgde
> - the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : 133:elnlyuxlcu

-First, I write my code:
```
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>

void pwncollege(char* argv[], char* env[]){
    char* aa[] = {"133=elnlyuxlcu", NULL};
    argv[295] = "jogxqfpgde";
    execve("/challenge/embryoio_level71", argv, aa);
    return;
}

int main(int argc, char* argv[], char* env)
{
    pid_t cpid;
    cpid = fork();
    if(cpid < 0){
        printf("error\n");
    }else if(cpid == 0){
        pwncollege(argv, env);
    }else{
        wait(NULL);
    }
    return 0;
}
```
-It has problem:
>[FAIL]    It looks like you did not pass enough arguments to the program.

-So, I try to fill the argv from 1 to 296(include 295) with "jogxqfpgde". Because, argv[0] is executable itself: `argv[0] = "embryoio_level71"`
-It work and get flag. Then, I replace "jogxqfpgde" with random string such as "abcd", and it still work. Finally, I use "" and also get this flag.
-Therefore, I guess if I don't input, program will understand this is Null and don't get anything, so agrument at number 295 won't be read.
    
```
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>

void pwncollege(char* argv[], char* env[]){
    char* aa[] = {"133=elnlyuxlcu", NULL};
    for(int i = 1; i < 296; i++)
        argv[i] = "";
    argv[295] = "jogxqfpgde";
    execve("/challenge/embryoio_level71", argv, aa);
    return;
}

int main(int argc, char* argv[], char* env)
{
    pid_t cpid;
    cpid = fork();
    if(cpid < 0){
        printf("error\n");
    }else if(cpid == 0){
        pwncollege(argv, env);
    }else{
        wait(NULL);
    }
    return 0;
}
```
# 72. Level 72:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will check that input is redirected from a specific file path : turefv
> - the challenge will check that it is running in a specific current working directory : /tmp/grzxyb

```
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>
#include<sys/stat.h>


void pwncollege(){
    pid_t pid;
    int fd = open("turefv", O_RDWR);
    if(fd < 0){
        perror("Open");
        return EXIT_FAILURE;
    }
    if((pid = fork()) < 0){
        perror("fork");
        return EXIT_FAILURE;
    } else if(!pid){
        dup2(fd, STDIN_FILENO);
        close(fd);
        execlp("/challenge/embryoio_level72", "embryoio_level72", NULL);
        perror("execlp");
        return EXIT_FAILURE;
    }else{
        close(fd);
        printf("Parrent waiting.\n");
        getchar();
    }
}
int main(int argc, char* argv[], char* env)
{
    pwncollege();
}
```
# 73. Level 73:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will check that it is running in a specific current working directory : /tmp/emsofg
> - the challenge will check to make sure that the parent's parent CWD to be different than the challenge's CWD

-In this challenge we will know about `chdir()`. You must to run this program in directory diffrent with /tmp/emsofg.
    
```
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>
#include<sys/stat.h>


void pwncollege(){
    pid_t pid;
    if((pid = fork()) < 0){
        perror("fork");
        return EXIT_FAILURE;
    } else if(!pid){
        chdir("/tmp/emsofg");
        execve("/challenge/embryoio_level73", NULL, NULL);
        perror("execlp");
        return EXIT_FAILURE;
    }else{
        printf("Parrent waiting.\n");
        getchar();
    }
}
int main(int argc, char* argv[], char* env)
{
    pwncollege();
}
```
# 74. Level 74:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 29:sjzzclepas

-You can do this. 
```
#!/usr/bin/env python3
from pwn import *
import subprocess

args = ["/challenge/embryoio_level74"]
for i in range(30):
    args.append("sjzzclepas")

r = process(args)
r.interactive()
```
-Or you can make:
```
#!/usr/bin/env python3
from pwn import *

p = process(["/challenge/embryoio_level74", *([''] * 28), 'sjzzclepas'])
p.interactive()
```
# 76. Level 76:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)
> - the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : 126:taskraphce
    
```
from pwn import *
r = process(["/challenge/embryoio_level76"], env ={"126":"taskraphce"})
r.interactive()
```
# 77. Level 77:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 36:xhgzegeywm
> - the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : 185:pfqthebkev

```
from pwn import *
r = process(["/challenge/embryoio_level77", *([''] * 35), "xhgzegeywm"], env ={"185": "pfqthebkev"})
r.interactive()
```
# 78. Level 78:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will check that input is redirected from a specific file path : covwsb
> - the challenge will check that it is running in a specific current working directory : /tmp/tjkaen
    
```
from pwn import *
o = open("covwsb", "r")
r = process("/challenge/embryoio_level78", stdin=o)
r.interactive()
```
# 79. Level 79
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will check that it is running in a specific current working directory : /tmp/vbdxfk
> - the challenge will check to make sure that the parent's parent CWD to be different than the challenge's CWD
    
```
from pwn import *
r = process(f'cd /tmp/vbdxfk; exec {"/challenge/embryoio_level79"}', shell=True)
r.interactive()
```
# 80. Level 80:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 141:cuiamgtkhb
    
```
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>
#include<sys/stat.h>


void pwncollege(char* argv[], char* env){
    pid_t pid;
    if((pid = fork()) < 0){
        perror("fork");
        return EXIT_FAILURE;
    } else if(!pid){
        for(int i = 1; i < 143; i++)
            argv[i] = "";
        argv[141] = "cuiamgtkhb";
        execve("/challenge/embryoio_level80", argv, NULL);
        perror("execve");
        return EXIT_FAILURE;
    }else{
        printf("Parrent waiting.\n");
        getchar();
    }
}
int main(int argc, char* argv[], char* env)
{
    pwncollege(argv, env);
}
```
# 82. Level 82:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)
> - the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : 269:rsmwsjnfls
    
```
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>
#include<sys/stat.h>


void pwncollege(char* argv[], char* env){
    pid_t pid;
    if((pid = fork()) < 0){
        perror("fork");
        return EXIT_FAILURE;
    } else if(!pid){
        char* new_env = {"269=rsmwsjnfls", NULL};
        execve("/challenge/embryoio_level82", argv, new_env);
        perror("execve");
        return EXIT_FAILURE;
    }else{
        printf("Parrent waiting.\n");
        getchar();
    }
}
int main(int argc, char* argv[], char* env)
{
    pwncollege(argv, env);
}
```
# 83. Level 83:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will check that the environment is empty (except LC_CTYPE, which is impossible to get rid of in some cases)
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 234:puzltwgeyb
> - the challenge will check that env[KEY] holds value VALUE (listed to the right as KEY:VALUE) : 341:jripfwmtnw                          

```
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>
#include<sys/stat.h>


void pwncollege(char* argv[], char* env){
    pid_t pid;
    if((pid = fork()) < 0){
        perror("fork");
        return EXIT_FAILURE;
    } else if(!pid){
        for(int i = 1; i < 236; i++){
            argv[i] = "";
        }
        argv[234] = "puzltwgeyb";
        char * new_env[] = {"341=jripfwmtnw", NULL};
        execve("/challenge/embryoio_level83", argv, new_env);
        perror("execve");
        return EXIT_FAILURE;
    }else{
        printf("Parrent waiting.\n");
        getchar();
    }
}
int main(int argc, char* argv[], char* env)
{
    pwncollege(argv, env);
}
```
# 84. Level 84:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will check that input is redirected from a specific file path : umxump
> - the challenge will check that it is running in a specific current working directory : /tmp/hdlwlv

```
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>
#include<sys/stat.h>


void pwncollege(char* argv[], char* env){
    pid_t pid;
    if((pid = fork()) < 0){
        perror("fork");
        return EXIT_FAILURE;
    } else if(!pid){
        chdir("/tmp/hdlwlv");
        int fd = open("umxump", O_CREAT | O_RDONLY);
        if(fd == -1){
            perror("Open");
            return EIXT_FAILURE;
        }
        dup2(fd, STDIN_FILENO);
        execve("/challenge/embryoio_level84", argv, env);
        perror("execve");
        return EXIT_FAILURE;
    }else{
        printf("Parrent waiting.\n");
        getchar();
    }
}
int main(int argc, char* argv[], char* env)
{
    pwncollege(argv, env);
}
```
# 85. Level 85:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will check that it is running in a specific current working directory : /tmp/wcfyzf
> - the challenge will check to make sure that the parent's parent CWD to be different than the challenge's CWD 
    
```
#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<fcntl.h>
#include<sys/stat.h>


void pwncollege(char* argv[], char* env){
    pid_t pid;
    if((pid = fork()) < 0){
        perror("fork");
        return EXIT_FAILURE;
    } else if(!pid){
        chdir("/tmp/wcfyzf");
        execve("/challenge/embryoio_level85", argv, env);
        perror("execve");
        return EXIT_FAILURE;
    }else{
        printf("Parrent waiting.\n");
        getchar();
    }
}
int main(int argc, char* argv[], char* env)
{
    pwncollege(argv, env);
}
```
# 86. Level 86:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will force the parent process to solve a number of arithmetic problems : 1
> - the challenge will use the following arithmetic operations in its arithmetic problems : +*
> - the complexity (in terms of nested expressions) of the arithmetic problems : 1

```
#!/bin/sh 
/challenge/embryoio_level86
```
# 87. Level 87:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will force the parent process to solve a number of arithmetic problems : 5
> - the challenge will use the following arithmetic operations in its arithmetic problems : +*%
> - the complexity (in terms of nested expressions) of the arithmetic problems : 3

```
#!/bin/sh 
/challenge/embryoio_level87
```
# 88. Level 88:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 0:/tmp/ozurcz

```
#!/bin/sh
ln -s /challenge/embryoio_level88 /tmp/ozurcz
/tmp/ozurcz
```
# 89. Level 89:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 0:luxqba

-See solution here:
https://askubuntu.com/questions/720678/what-does-export-path-somethingpath-mean
https://opensource.com/article/17/6/set-path-linux
```
#!/bin/sh
cd /tmp
ln -s /challenge/embryoio_level89 /tmp/luxqba
PATH=PATH:/tmp
luxqba
```
# 89. Level 89:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will make sure that stdin is redirected from a fifo
> - the challenge will check for a hardcoded password over stdin : lflfxmio

-See solution here:
    https://stackoverflow.com/questions/4113986/example-of-using-named-pipes-in-linux-shell-bash
```
#!/bin/sh
mkfifo /tmp/test
echo lflfxmio > /tmp/test &
/challenge/embryoio_level90 < /tmp/test
```
# 91. Level 91:                                   
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will make sure that stdout is a redirected from fifo                               ```
 
#!/bin/sh
mkfifo /tmp/test
/challenge/embryoio_level91 > /tmp/test &
cat /tmp/test 
  
# 92. Level 92:
    
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will make sure that stdin is redirected from a fifo
> - the challenge will make sure that stdout is a redirected from fifo
> - the challenge will check for a hardcoded password over stdin : lcugoznd

```
#!/bin/sh
mkfifo /tmp/test1
mkfifo /tmp/test2
echo lcugoznd > /tmp/test1 &
/challenge/embryoio_level92 < /tmp/test1  > /tmp/test2 &
cat /tmp/test2
```
# 93. Level 93:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will make sure that stdin is redirected from a fifo
> - the challenge will make sure that stdout is a redirected from fifo
> - the challenge will force the parent process to solve a number of arithmetic problems : 1
> - the challenge will use the following arithmetic operations in its arithmetic problems : +*
> - the complexity (in terms of nested expressions) of the arithmetic problems : 1

`pwn.college{8sFahb-d7iiIkic4Iuv2hmVXksp.QXzkDL2ITN3MzW}`
-In this level, I search the solution in other people, and see that:
```
#!/bin/sh
rm /tmp/test_out; mkfifo /tmp/test_out
rm /tmp/test_in; mkfifo /tmp/test_in
rm /tmp/peek; mkfifo /tmp/peek

/challenge/embryoio_level93 </tmp/test_in >/tmp/test_out &
LANG=C perl -ne 'print (eval $1) && exit if /for: (.*)\n/' >/tmp/test_in </tmp/peek &
cat /tmp/test_out | tee /tmp/peek
```
-However, I run several times to get flag. We will study about powefull command Linux `perl`.
-I will study it later....
# 94. Level 94:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will take input on a specific file descriptor : 217
> - the challenge will check for a hardcoded password over stdin : yzrhwcwn

```
#!/bin/sh
echo yzrhwcwn | exec 217<&0 /challenge/embryoio_level94
```
# 95. Level 95:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will take input on a specific file descriptor : 2
> - the challenge will check for a hardcoded password over stdin : praegoxs                            
```
#!/bin/sh
echo praegoxs | exec 2<&0 /challenge/embryoio_level95
```       
# 96. Level 96:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will take input on a specific file descriptor : 1
> - the challenge will check for a hardcoded password over stdin : eymxwqlm                     

```
#!/bin/sh
/challenge/embryoio_level96
```
# 97, 98. Level 97 && Level 98:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will require the parent to send number of signals : 1

> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will require the parent to send number of signals : 5
    
-Create two tabs to connect to Dojo. When the challenge requires a request, let's do it.

.
# 99. Level 99:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will force the parent process to solve a number of arithmetic problems : 1
> - the challenge will use the following arithmetic operations in its arithmetic problems : +*
> - the complexity (in terms of nested expressions) of the arithmetic problems : 1

```
from pwn import *
r = process('/challenge/embryoio_level99')
r.interactive() 
```   
# 100. Level 100:
> WELCOME! This challenge makes the following asks of you:    
> - the challenge checks for a specific parent process : python
> - the challenge will force the parent process to solve a number of arithmetic problems : 5
> - the challenge will use the following arithmetic operations in its arithmetic problems : +*%
> - the complexity (in terms of nested expressions) of the arithmetic problems : 3
    
```
from pwn import *
r = process('/challenge/embryoio_level100')
r.interactive() 
```  
# 101. Level 101:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 0:/tmp/yedczc

`ln -s /challenge/embryoio_level101 /tmp/yedczc`
```
from pwn import *
r = process('/tmp/yedczc')
r.interactive() 
```
# 102. Level 102:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 0:sblwyd

`ln -s /challenge/embryoio_level102 sblwyd`
```
export PATH=$PATH
```
```
from pwn import *
r = process('sblwyd')
r.interactive()
```
# 103. Level 103:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will make sure that stdin is redirected from a fifo
> - the challenge will check for a hardcoded password over stdin : ulwgarwf
 
```
from pwn import *
import os
import glob
fifo_in = "/tmp/fifo"

if os.path.exists(fifo_in):
    os.remove(fifo_in)
os.mkfifo(fifo_in, mode=0o777)

fifo_in_r = os.open(fifo_in, os.O_RDWR)
fifo_in_w = os.open(fifo_in, os.O_WRONLY)

p0 = process(['cat', '-'], stdout=fifo_in_w)
p0.sendline(b'ulwgarwf')
p = process('/challenge/embryoio_level103', stdin=fifo_in_r)

p.interactive()

close(fifo_in_r)
close(fifo_in_w)
```
# 104. Level 104:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will make sure that stdout is a redirected from fifo

```
from pwn import *
import subprocess
import glob

fifo_in = "/tmp/fifo"
if os.path.exists(fifo_in):
    os.remove(fifo_in)

os.mkfifo(fifo_in, mode=0o777)
fifo_in_r = os.open(fifo_in, os.O_RDWR)
fifo_in_w = os.open(fifo_in, os.O_WRONLY)

p = process("/challenge/embryoio_level104", stdout=fifo_in_w)

r = process(['cat', '-'], stdin=fifo_in_r)
r.interactive()
close(fifo_in_r)
close(fifo_in_w)
```   
# 105. Level 105:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will make sure that stdin is redirected from a fifo
> - the challenge will make sure that stdout is a redirected from fifo
> - the challenge will check for a hardcoded password over stdin : nyrxdmgy

```
from pwn import *
import os
import glob

fifo_in = "/tmp/fifo_in"
fifo_out = "/tmp/fifo_out"

if os.path.exists(fifo_in):
    os.remove(fifo_in)
if os.path.exists(fifo_out):
    os.remove(fifo_out)
os.mkfifo(fifo_in, mode=0o777)
fifo_in_r = os.open(fifo_in, os.O_RDWR)
fifo_in_w = os.open(fifo_in, os.O_WRONLY)

os.mkfifo(fifo_out, mode=0o777)
fifo_out_r = os.open(fifo_out, os.O_RDWR)
fifo_out_w = os.open(fifo_out, os.O_WRONLY)

In = process(['cat', '-'], stdout=fifo_in_w)
In.sendline(b'nyrxdmgy')

r = process('/challenge/embryoio_level105', stdin=fifo_in_r, stdout=fifo_out_w)

out = process(['cat', '-'], stdin=fifo_out_r)
out.interactive()

close(fifo_in)
close(fifo_out)
```
# 106. Level 106:
```
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : python
- the challenge will make sure that stdin is redirected from a fifo
- the challenge will make sure that stdout is a redirected from fifo
- the challenge will force the parent process to solve a number of arithmetic problems : 1
- the challenge will use the following arithmetic operations in its arithmetic problems : +*
- the complexity (in terms of nested expressions) of the arithmetic problems : 1
```

-I search solution:
    https://github.com/Cipher731/pwn_college_writeup/blob/main/1.interaction/embryoio_level106.py#L20
```
import fcntl
import glob
import os
import tempfile
import time

from pwn import *


def make_and_open_fifo():
    fifo_path = os.path.join(tempfile.mkdtemp(), 'myfifo')
    os.mkfifo(fifo_path, 0o666)

    temp_fd0 = os.open(fifo_path, os.O_RDONLY | os.O_NONBLOCK)
    temp_fd1 = os.open(fifo_path, os.O_WRONLY | os.O_NONBLOCK)

    return (temp_fd0, temp_fd1)


bin_path = glob.glob('/challenge/embryoio_level106')[0]

# Write ==>[1 fd0 0]==> Challenge ==>[1 fd1 0]==> Read
fd0 = make_and_open_fifo()
fd1 = make_and_open_fifo()

# Unset NONBLOCK Read. Otherwise, the checker would read EOF from stdin and mess up
oldfl = fcntl.fcntl(fd0[0], fcntl.F_GETFL)
fcntl.fcntl(fd0[0], fcntl.F_SETFL, oldfl & ~os.O_NONBLOCK)

p = process([bin_path], stdin=fd0[0], stdout=fd1[1])

time.sleep(0.5)
challenge = os.read(fd1[0], 4096).decode()
challenge = challenge.split('solution for: ')[-1].strip()

response = str(eval(challenge))
os.write(fd0[1], response.encode())
os.close(fd0[1])  # Close is a must when using blocking read mode

time.sleep(1)
print(os.read(fd1[0], 4096).decode())
```
# 107. Level 107:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will take input on a specific file descriptor : 82
> - the challenge will check for a hardcoded password over stdin : aahlhpgt
    
```
import subprocess
import os
import glob
from pwn import *

fd = os.pipe()
os.dup2(fd[0], 82)
p = subprocess.Popen('/challenge/embryoio_level107', pass_fds=(82,))
os.write(fd[1], b'aahlhpgt')

time.sleep(1)
print(p.read(4096).decode())
```
# 108. Level 108:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will take input on a specific file descriptor : 2
> - the challenge will check for a hardcoded password over stdin : fajrzboq
    
```
import subprocess
import os
import glob
from pwn import *

fd = os.pipe()
os.dup2(fd[0], 82)
p = subprocess.Popen('/challenge/embryoio_level108', pass_fds=(82,))
os.write(fd[1], b'fajrzboq')

time.sleep(1)
print(p.read(4096).decode())
```
# 109. Level 109:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will take input on a specific file descriptor : 1
> - the challenge will check for a hardcoded password over stdin : yrrjpunw
    
```
import subprocess
import os
import glob
from pwn import *

bin_path = glob.glob('/challenge/embryoio_level109')[0]
p = subprocess.Popen([bin_path])
time.sleep(4)
p.wait()
```
# 110. Level 110:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : python
> - the challenge will require the parent to send number of signals : 1
    
-Create two tabs connect to Dojo. When the challenge requires the request, let's do it.

```
import subprocess
import os
import glob
from pwn import *

bin_path = glob.glob('/challenge/embryoio_level110')[0]
p = subprocess.Popen([bin_path])
time.sleep(4)
p.wait()
```
# 101. Level 101:
WELCOME! This challenge makes the following asks of you:
- the challenge checks for a specific parent process : python
- the challenge will require the parent to send number of signals : 5
    
-Create two tabs connect to Dojo. When the challenge requires the request, let's do it.

```
import subprocess
import os
import glob
from pwn import *

bin_path = glob.glob('/challenge/embryoio_level111')[0]
p = subprocess.Popen([bin_path])
time.sleep(4)
p.wait()
```
# 112. Level 112:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will force the parent process to solve a number of arithmetic problems : 1
> - the challenge will use the following arithmetic operations in its arithmetic problems : +*
> - the complexity (in terms of nested expressions) of the arithmetic problems : 1

```
#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>

void pwncollege(){
    int fork1 = fork();
    if(fork1 == 0){
        char* filename = "/challenge/embryoio_level112";
        pid_t cpid;
        int fork2 = fork();
        if(fork2 >  0){
            execve(filename, NULL, NULL);
        }else if(fork2 == 0){
            wait(NULL);
        }else{
                printf("There are some wrong in fork2");
        }
    }else{
        waitpid(fork1, NULL, 0);
    }
}
int main()
{
    pwncollege();
    return 0;
}
```
# 113. Level 113:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will force the parent process to solve a number of arithmetic problems : 5
> - the challenge will use the following arithmetic operations in its arithmetic problems : +*%
> - the complexity (in terms of nested expressions) of the arithmetic problems : 3

-This challenge is similar to challenge 112.
# 114. Level 114:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 0:/tmp/tfnzse
    
```
#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>

void pwncollege(int argc, char* argv[]){
    argv[0] = "/tmp/tfnzse";
    int fork1 = fork();
    if(fork1 == 0){
        char* filename = "/challenge/embryoio_level114";
        pid_t cpid;
        int fork2 = fork();
        if(fork2 >  0){
            execve(filename, argv, NULL);
        }else if(fork2 == 0){
            wait(NULL);
        }else{
                printf("There are some wrong in fork2");
        }
    }else{
        waitpid(fork1, NULL, 0);
    }
}
int main(int argc, char* argv[])
{
    pwncollege(argc, argv);
    return 0;
}
```
# 115. Level 115:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will check that argv[NUM] holds value VALUE (listed to the right as NUM:VALUE) : 0:wmzivw

```
#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>

void pwncollege(int argc, char* argv[]){
    argv[0] = "wmzivw";
    int fork1 = fork();
    if(fork1 == 0){
        char* filename = "/challenge/embryoio_level115";
        pid_t cpid;
        int fork2 = fork();
        if(fork2 >  0){
            execve(filename, argv, NULL);
        }else if(fork2 == 0){
            wait(NULL);
        }else{
                printf("There are some wrong in fork2");
        }
    }else{
        waitpid(fork1, NULL, 0);
    }
}
int main(int argc, char* argv[])
{
    pwncollege(argc, argv);
    return 0;
}
```
# 116. Level 116:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will make sure that stdin is redirected from a fifo
> - the challenge will check for a hardcoded password over stdin : sgamfrqe

```
#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>
#include <stdlib.h>
#include <glob.h>
#include <sys/stat.h>
#include <libgen.h>
#include <fcntl.h>
#include<errno.h>

void pwncollege(){
    char* filename = "/challenge/embryoio_level116";
    mkfifo("/tmp/fifo", 0777);
    int i = fork();
    if(i > 0){
        int fd = open("/tmp/fifo", O_WRONLY);
        if(fd == -1){
            perror("Open file");
            exit(0);
        }
        write(fd, "sgamfrqe", 8);
        close(fd);
        wait(NULL);
    }else if(i ==0){
        int fd = open("/tmp/fifo", O_RDONLY);
        if(fd == -1){
            perror("Open file");
            exit(0);
        }
        dup2(fd, 0);
        execve(filename, NULL, NULL);
    }
}
int main(){
    pwncollege();
    return 0;
}
```
# 117. Level 117:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will make sure that stdout is a redirected from fifo

```
#include<stdio.h>
#include<unistd.h>
#include<sys/wait.h>
#include <stdlib.h>
#include <glob.h>
#include <sys/stat.h>
#include <libgen.h>
#include <fcntl.h>
#include<errno.h>

void pwncollege(){
    char* filename = "/challenge/embryoio_level117";
    mkfifo("/tmp/fifo", 0777);
    int k = fork();
    if(k == 0){
        int i = fork();
        if(i > 0){
            int fd = open("/tmp/fifo", O_WRONLY);
            if(fd == -1){
                perror("Open file");
                exit(0);
            }
            dup2(fd, 1);
            execve(filename, NULL, NULL);
            close(fd);
            wait(NULL);
        }else if(i ==0){
            FILE *fp;
            int c;
            fp = fopen("/tmp/fifo","r");
            while(1) {
                c = fgetc(fp);
                if( feof(fp) ) { 
                    break ;
                }
                printf("%c", c);
            }
            fclose(fp);
        }
    }else {
        waitpid(k, NULL, 0);
    }
}
int main(){
    pwncollege();
    return 0;
}
```
# 118. Level 118:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will make sure that stdin is redirected from a fifo
> - the challenge will make sure that stdout is a redirected from fifo
> - the challenge will check for a hardcoded password over stdin : jmzagqpi
    
-I spent many times for this challenge. To be honest, I don't know why I can get the flag =))))
-First, I create two fork and use method simmilar to level 117 to restricted output to other fifo and **It don't work**.
    
```
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <glob.h>
#include <sys/stat.h>
#include <libgen.h>
#include <fcntl.h>
#include <errno.h>

void pwncollege()
{
    char *filename = "/challenge/embryoio_level118";
    mkfifo("/tmp/fifo_in", 0777);
    mkfifo("/tmp/fifo_out", 0777);

    int fork_it = fork();
    if (fork_it > 0)
    {
        int fd_in = open("/tmp/fifo_in", O_WRONLY);
        if (fd_in == -1)
        {
            perror("Open file:");
            exit(0);
        }
        int fd_out = open("/tmp/fifo_out", O_RDONLY);
        if (fd_out == -1)
        {
            perror("Open file:");
            exit(0);
        }
        write(fd_in, "jmzagqpi", 8);
        close(fd_in);
        wait(NULL);
        char buf[4096] = {};
        read(fd_out, buf, 4096);
        write(1, buf, 4096);
    }
    else if (fork_it == 0)
    {
        int fd_in = open("/tmp/fifo_in", O_RDONLY);
        if (fd_in == -1)
        {
            perror("Open file:");
            exit(0);
        }
        int fd_out = open("/tmp/fifo_out", O_WRONLY);
        if (fd_out == -1)
        {
            perror("Open file:");
            exit(0);
        }
        dup2(fd_in, 0);
        dup2(fd_out, 1);
        execve(filename, NULL, NULL);
    }
}
int main()
{
    pwncollege();
    return 0;
}
```
# 119. Level 119:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will make sure that stdin is redirected from a fifo
> - the challenge will make sure that stdout is a redirected from fifo
> - the challenge will force the parent process to solve a number of arithmetic problems : 1
> - the challenge will use the following arithmetic operations in its arithmetic problems : +*
> - the complexity (in terms of nested expressions) of the arithmetic problems : 1

# 120. Level 120:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will take input on a specific file descriptor : 56
> - the challenge will check for a hardcoded password over stdin : ozsyamkq
    
```
#include <stdlib.h>
#include <unistd.h>
#include <glob.h>
#include <sys/wait.h>
#include <libgen.h>
#include <fcntl.h>

char* filename = "/challenge/embryoio_level120";

void pwncollege() {
    if (fork()) {
        wait(NULL);
    } else {
        dup2(0, 56);
        execve(filename, NULL, NULL);
    }
}

int main() {
    pwncollege();
}
```
# 121. Level 121:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will take input on a specific file descriptor : 2
> - the challenge will check for a hardcoded password over stdin : xtiixhsm
    
```
#include <stdlib.h>
#include <unistd.h>
#include <glob.h>
#include <sys/wait.h>
#include <libgen.h>
#include <fcntl.h>

char* filename = "/challenge/embryoio_level121";

void pwncollege() {
    if (fork()) {
        wait(NULL);
    } else {
        dup2(0, 2);
        execve(filename, NULL, NULL);
    }
}

int main() {
    pwncollege();
}
```
# 122. Level 122:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will take input on a specific file descriptor : 1
> - the challenge will check for a hardcoded password over stdin : fkkunhbv

```
#include <stdlib.h>
#include <unistd.h>
#include <glob.h>
#include <sys/wait.h>
#include <libgen.h>
#include <fcntl.h>

char* filename = "/challenge/embryoio_level122";

void pwncollege() {
    if (fork()) {
        wait(NULL);
    } else {
        dup2(0, 1);
        execve(filename, NULL, NULL);
    }
}

int main() {
    pwncollege();
}
```
# 123. Level 123:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will require the parent to send number of signals : 1

-Create two tabs and connect to dojo, one run challenge and one kill signal
```
#include <stdlib.h>
#include <unistd.h>
#include <glob.h>
#include <sys/wait.h>
#include <libgen.h>
#include <fcntl.h>

char* filename = "/challenge/embryoio_level123";

void pwncollege() {
    if (fork()) {
        wait(NULL);
    } else {
        execve(filename, NULL, NULL);
    }
}

int main() {
    pwncollege();
}
```
# 124. Level 124:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : binary
> - the challenge will require the parent to send number of signals : 5
    
-Create two tabs and connect to dojo, one run challenge and one kill 5 signals
```
#include <stdlib.h>
#include <unistd.h>
#include <glob.h>
#include <sys/wait.h>
#include <libgen.h>
#include <fcntl.h>

char* filename = "/challenge/embryoio_level124";

void pwncollege() {
    if (fork()) {
        wait(NULL);
    } else {
        execve(filename, NULL, NULL);
    }
}

int main() {
    pwncollege();
}
```
# 125. Level 125:
> WELCOME! This challenge makes the following asks of you:
> - the challenge checks for a specific parent process : shellscript
> - the challenge will force the parent process to solve a number of arithmetic problems : 50
> - the challenge will use the following arithmetic operations in its arithmetic problems : +*&^%|
> - the complexity (in terms of nested expressions) of the arithmetic problems : 5

-I search solution here:
https://github.com/Cipher731/pwn_college_writeup/blob/main/1.interaction/embryoio_level125_126.sh
```
#!/usr/bin/sh
rm /tmp/test_out; mkfifo /tmp/test_out
rm /tmp/test_in; mkfifo /tmp/test_in
rm /tmp/peek; mkfifo /tmp/peek

cat <<EOF > /tmp/py_script
while True:
    line = input()
    chal = line.find('for: ')
    if chal > 0: 
        print(eval(line[chal+4:].strip()))
EOF

/challenge/embryoio* </tmp/test_in >/tmp/test_out &
python /tmp/py_script >/tmp/test_in </tmp/peek &
cat /tmp/test_out | tee /tmp/peek
```
    
