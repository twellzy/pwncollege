from pwn import *

file = "/challenge/babymem_level14.1"
ip = "127.0.0.1"
port = 1337

p = remote(ip, port)

p.sendline(b'1')
p.sendline(b'a')
test = p.recvuntil(b'asfdasdfasdf', timeout=0.1)
print(test)
print(len(test))
