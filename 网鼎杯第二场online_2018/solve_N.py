from Crypto.PublicKey import RSA
import libnum
import gmpy2
from base64 import b64decode

pubkey1 = RSA.importKey(open("pubkey1.pem").read())
pubkey2 = RSA.importKey(open("pubkey2.pem").read())
c1 = libnum.s2n(b64decode(open("flag1.enc").read()))
c2 = libnum.s2n(b64decode(open("flag2.enc").read()))
print c1,c2
print pubkey1.e
print pubkey1.n
print pubkey2.e
print pubkey2.n
print pubkey1.n == pubkey2.n
print gmpy2.gcd(pubkey1.e, pubkey2.e)
gcd, s, t = gmpy2.gcdext(pubkey1.e, pubkey2.e)
if s < 0:
    s = -s
    c1 = gmpy2.invert(c1, pubkey1.n)
if t < 0:
    t = -t
    c2 = gmpy2.invert(c2, pubkey1.n)
m = gmpy2.powmod(c1, s, pubkey1.n) * gmpy2.powmod(c2, t, pubkey1.n) % pubkey1.n
print libnum.n2s(m)