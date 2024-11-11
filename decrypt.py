from pwn import *
import base64
import binascii
#ELEMENTS ARE HARD CODED MUST FIX
p = process('/challenge/run')
flagLen = 58

characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()-_+=[]{}\|;:\'\",<.>/?`~ "
padding = [b"\x01",b"\x02",b"\x03",b"\x04",b"\x05",b"\x06",b"\x07",b"\x08",b"\x09",b"\x0A",b"\x0B",b"\x0C",b"\x0D",b"\x0E",b"\x0F"]
p.recvuntil(b'plaintext prefix (b64): ')

p.sendline(base64.b64encode(b'a'*7))
p.recvuntil(b'(hex): ')

check = p.recvuntil(b'p')
print(check)

p.sendline(base64.b64encode(b'\x0A'+padding[14]*15))
p.recvuntil(b'(hex): ')

guess = p.recvuntil(b'p')
print(guess)

check = check[len(check)-35:len(check)-3]
guess = guess[0:32]


p.recvuntil(b'(b64): ')


def loop(a,pad,previousCharacters):
    p.sendline(base64.b64encode(b'a'*a))

    check = p.recvuntil(b'p')
    check = check[len(check)-35:len(check)-3]

    p.recvuntil(b'(hex): ')

    check = p.recvuntil(b'p')
    check = check[len(check)-35:len(check)-3]
    flag = ''

    for char in characters:
        guesschar = char.encode('utf-8')
        p.sendline(base64.b64encode(guesschar+previousCharacters+b'\x0A'+padding[pad]*(pad+1)))
        p.recvuntil(b'(hex): ')

        guess = p.recvuntil(b'p')
        guess = guess[0:32]
        if guess == check:
            print('here')
            flag = flag + char
            break

    p.recvuntil(b'(b64): ')
    return flag

def loop2(a, flagPart, blockNumber):
    p.sendline(base64.b64encode(b'a'*a))

    p.recvuntil(b'(hex): ')

    check = p.recvuntil(b'p')
    check = check[len(check)-(35 + 33*blockNumber):len(check)-(3 + 33*blockNumber)]
    flag = ''
    for char in characters:
        guesschar = char.encode('utf-8')
        p.sendline(base64.b64encode(guesschar+flagPart))
        p.recvuntil(b'(hex): ')

        guess = p.recvuntil(b'p')
        guess = guess[0:32]
        if guess == check:
            flag = flag + char
            break

    p.recvuntil(b'(b64): ')
    return flag


a = 9
pad = 12
flag = '}'
for i in range(13):
    character = loop(a, pad, flag.encode('utf-8'))
    flag = ''.join((character,flag))
    print(flag)
    pad -= 1
    a += 1

#flag = 'NzMDL5UTMzUzW}'
sflag = flag
a = 7


p.sendline(base64.b64encode(b'a'*6))

p.recvuntil(b'(hex): ')

check = p.recvuntil(b'p')
check = check[len(check)-68:len(check)-36]

for char in characters:
    guesschar = char.encode('utf-8')
    newflag = flag.encode('utf-8')
    p.sendline(base64.b64encode(guesschar+newflag+b'\x0A'))
    p.recvuntil(b'(hex): ')

    guess = p.recvuntil(b'p')
    guess = guess[0:32]
    if guess == check:
        flag = ''.join((char, flag))
        break

p.recvuntil(b'(b64): ')

print(flag)
a = 7
for i in range(16):
    flagpart = flag[0:15]
    print(flagpart)
    character = loop2(a, flagpart.encode('utf-8'), 1)
    flag = ''.join((character, flag))
    a += 1
    print(flag)

a = 6

for i in range(16):
    flagpart = flag[0:15]
    print(flagpart)
    character = loop2(a, flagpart.encode('utf-8'), 2)
    flag = ''.join((character, flag))
    a += 1
    print(flag)

