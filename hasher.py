from Crypto.Hash.SHA256 import SHA256Hash
from pwn import *
import base64
p = process('/challenge/run')
p.recvuntil(b'(b64): ')

done = False
index = 0
challenge = p.recvuntil(b'\x0A')
challenge = challenge[:-1]
challenge = base64.b64decode(challenge)



collisionHash = b'\x00\x00'
while not done:
	bindex = index.to_bytes(4, "big")
	sha256 = SHA256Hash()
	sha256.update(challenge + bindex)
	checkhash = sha256.digest()
	checkhash = checkhash[:2]
	print(checkhash)
	if checkhash == collisionHash:
		collision = base64.b64encode(bindex)
		print(collision)
		print(p.sendline(collision))
		print(p.recvline())
		print(p.recvline())
		done = True
	index += 1

	
