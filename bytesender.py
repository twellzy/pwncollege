#!/usr/bin/env python3

from pwn import *

p = process('/challenge/babyrev_level14.1')

p.sendline(b'\x14\xce\xf7\x45')
print(p.recvuntil(b'flag: '))
print(p.recvline())
