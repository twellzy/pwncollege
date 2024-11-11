from pwn import *
import sys
import string
import random
import pathlib
import base64
import json
import textwrap

from Crypto.Cipher import AES
from Crypto.Hash.SHA256 import SHA256Hash
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Random.random import getrandbits, randrange
from Crypto.Util.strxor import strxor
from Crypto.Util.Padding import pad, unpad


ciphertext = b'pAD4lawpD7KhM7pkdxq32USXa0uvleEXemeNExHX7WsM56vzZtzTPjeDxiiH98WXnkWE+NHpe2sb15dVFHouAALvomaYcBFDvY7ekPoW7QKFO3+p8Z15IxPO/Q6ipZCDvkPKEhT3yR4IA9LLghIEo8YcEOFyUAgo2rbTokRq4zzkP2iMlU7e1H3Lkj97g0k9H6MG2QJxoDTpiPd1y2yyj8rnMFC8l7j4BFyli77IRziLbx2GPWClw2VUi2bfha4iUG5lDMkBBosDvshtfUZ8rUrBwB7g9SsSvY/JXu7L0MqQfGOGpTRG2GAvtfOfxi1BnhofYF7zqDPDDyO4R521KA=='

#print(sys. getsizeof(ciphertext))
ciphertext = base64.b64decode(ciphertext)
ciphertext = int.from_bytes(ciphertext, "little")
#print(ciphertext)

p = int(614164848518235246773231529387231441096507808654821111434167966308465563986307602721743890916906513558864181237453284202930453626950162234339754478693)
q = int(959195684919098644780045002795606066548295482892843925524529532945311308572932940081752555260083997689454668426921799611587445106107134412896923446507)

b = 2**1025
phin = (p-1)*(q-1)
g = int(0x2)
n1 = 20419545350684183340341042196477776130068658184840135593019002999580038232631989076016967573112053047280890942456575139350259944244756737628058999672168193739869904802658306275161890011739525243153955946245808140284010092762736676132381886488640086955915670173494362904053565254395022269750669175848907271221098930220565127491699246532989337542092032715746663385295024935288447737409899268021973788355434690550377822921357212309775930022454648554628442979507693244889706584979857281431293201327606277667843412235940930785399952208746359518838133023122186516863781608202340522108557056213318772865457778577575891893647
n2 = p*q
#print(hex(n))
e = int(0x10001)

moduloP = int(0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff)
name = "xillmnnjkslcggtz"
#d = int(0x96a09a83070073a8e5e870b52cbcfa1b002c37d944f6eaaaf7817fdd10570af60a29cfdc484ccbe5e9c79af317c728730510e39c0aa00ef40db968f24b79d5ff81adc7ab2f852ce42b9373f04998245b4b777069a105aee3623ade273d3d6ebeeb7a7df8723f2afbe413f04dcb118b8bc9e231c5c8b9465d22a01eadd3560ef70e3d716b7b8d3831f9f96205cbd8175f19c02810e9e48555ef60b0ecdc92c2a227691a4fda894a416b55cfe329eabfe1a8ebbfeee7b2aee998e3676c3b3bf87fae47a8102e67ba4e1e92b22c247d70560a3330fd6ee537de23fd454091a785ec409683ea8e8c72320188fa120cc98bff4cd87f959656eae5d02b97fafe55c99)
challenge = int(0xd8ef1d3ea791f4dca18f2abf70a4fdc51d1b19d512d1c159c32f0da22b818c36ca6e0f6d2f3830e4cd2375c503a5bc5f38c7ca503f566ae0143d2d3d767144de)
d = pow(e, -1, phin)
#response = pow(challenge, d, int(n))
#print(hex(response))
#flag = flag.to_bytes(sys. getsizeof(flag), "little")
#flag = base64.b64encode(flag)
#print(base64.b64decode(flag))

user_certificate = {
        "name": name,
        "key": {
            "e": int(0x10001),
            "n": n2,
        },
        "signer": "root",
    }
user_certificate_data = json.dumps(user_certificate).encode()
user_certificate_hash = SHA256Hash(user_certificate_data).digest()


#print('\n')

user_certificate_signature = pow(
        int.from_bytes(user_certificate_hash, "little"),
        int(0x19dcdbef39be707e1313278d235e5b904400c72ed5950f548477f862ff8b2b278c660aaec936c6a2d6dc504e929104fddc9e113b89d8b480371ddd7abec4bc5e371dbbcec9aa348466434a374f2965ee0e84d0b1866767a58ee038db488304f8cef80c7e548f2dd3addff4ba0bb1cf06c4b40ca496ad76b31f815791a64ed71bb53d01666328355445a10f80b5f616053b3de2a1e6afc6600da3fdc2fb8a2a9dfa13542516fd06b7ddf5244e93eab0fec24929cb316af117fff406d5d334f79a0beecad7fbc77bd0708bf7a80dd50296375e43d0ebcc72ded877992d19b0f353a612793f9e68a77de3a41178acc010b7a4b69efa3fe1c46708fb5bc5fc1bc701),
        n1
    ).to_bytes(256, "little")

#print(base64.b64encode(user_certificate_signature))
ciphertext = b'pqAJPI5PD+4Ttn9rIn3gPHvzNkyy3jXuRawfo0AUZaevrJkQaqYbH2hrxYyFWZ9uUI5wCzA/IC8B0OeA/yB3xA=='

ciphertext = base64.b64decode(ciphertext)
ciphertext = int.from_bytes(ciphertext, 'big')
ciphertext = pow(ciphertext, d, n2)
ciphertext = ciphertext.to_bytes(sys.getsizeof(ciphertext), 'little')
ciphertext = base64.b64encode(ciphertext)
print(base64.b64decode(ciphertext))

B = pow(g, b, moduloP)

#print(hex(B))
#print('\n')
A = int(0x65873315582b46389eb9f79f44a95090206f3ddc0b0596efa966b9db6ab77527c38004ec97760701ca7c064559cb433da294708d79e9e88a3be5a21d2ae601ae83dc66f49dedfe1dd73befc35b78776f2943e1ee544f0b5d941a48b420d93cfd55bad6849a9e1e0358072e939e9fadcf857b3e3b19f86af5338236b11b93b57d0aaf28dd27efeb7048a4202128d99571a75870790ab6ebcb9ffc873f07298b611942984c980b952ac13d1e4bc956d0787c25a795d6f52778651d3b7bfe40be121976d338edf359fdf31bc1acde99b4f7be01531b122344026db730bb73cbeed5e39f790930d2c25ab6bbb693c7f56c9096d46e3efb6bd0ef91c8ee5566d5f4ad)

s = pow(A, b, moduloP)


key = SHA256Hash(s.to_bytes(256, "little")).digest()[:16]
cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)
cipher2 = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)
ct_bytes = cipher.encrypt(pad(user_certificate_data, cipher.block_size))
ct_bytes = base64.b64encode(ct_bytes)
#ct_bytes = unpad(cipher2.decrypt(base64.b64decode(ct_bytes)), cipher2.block_size)

#print(ct_bytes)
##print('\n')
s_bytes = cipher.encrypt(pad(user_certificate_signature, cipher.block_size))
s_bytes = base64.b64encode(s_bytes)
#print(s_bytes)
#print('\n')
#cipher_decrypt = AES.new(key=key, mode=AES.MODE_CBC, iv=b"\0"*16)

user_signature = (
        name.encode().ljust(256, b"\0") +
        A.to_bytes(256, "little") +
        B.to_bytes(256, "little")
    )

user_signature_hash = SHA256Hash(user_signature).digest()

user_signature = pow(
        int.from_bytes(user_signature_hash, "little"),
        d,
        n2
    ).to_bytes(256, "little")

user_signature = cipher.encrypt(pad(user_signature, cipher.block_size))
user_signature = base64.b64encode(user_signature)





#print('\n')
#print(user_signature)

ciphertext = b'pqAJPI5PD+4Ttn9rIn3gPHvzNkyy3jXuRawfo0AUZaevrJkQaqYbH2hrxYyFWZ9uUI5wCzA/IC8B0OeA/yB3xA=='


ciphertext = unpad(cipher2.decrypt(base64.b64decode(ciphertext)), cipher2.block_size)

print(ciphertext)