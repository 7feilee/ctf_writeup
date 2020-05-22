from sage.all import *
from Crypto.Util.number import long_to_bytes,bytes_to_long
import uuid
hlen=lambda x:len(hex(x)[2:].strip('L'))

def ntopoly(npoly):
    return sum(c*X**e for e, c in enumerate(Integer(npoly).bits()))

def polyton(poly):
    if not hasattr(poly, 'list'):
        poly = poly.polynomial()
    a = poly.list()
    return sum(int(a[i])*(1 << i) for i in range(len(a)))

def process(m):
    return polyton((ntopoly(m)**2))

def calc(m,p):
    res=0
    lens=hlen(p)
    for i in bin(m)[2:]:
        res*=2
        res^^=m if i=='1' else 0
        res^^=p if hlen(res) == lens else 0
    return res

def enc(flag):
    r = 4
    cts = []
    for i in range(4):
        cts.append(calc(bytes_to_long(flag[:r]),0x8025 + (1<<r*8)))
        flag = flag[r:]
        r *= 2
    return cts

flag = str(uuid.uuid4()).encode()
cts = enc(flag)
r = 4
decrypt = b""
x = var('x')
X = GF(2).polynomial_ring().gen()
for ct in cts:
    p = (1<<r*8) + 0x8025
    r*=2
    residues = []
    moduli = []
    for poly,_ in ntopoly(p).factor():
        degree = poly.degree()
        moduli.append(poly)
        X = GF(2).polynomial_ring().gen()
        F = GF(2^degree, 'z'+str(degree), modulus=poly)
        X = F.gen()
        residue = polyton(ntopoly(ct).sqrt())
        X = GF(2).polynomial_ring().gen()
        residues.append(ntopoly(residue))
    decrypt+=long_to_bytes(polyton(crt(residues,moduli)))
print(flag)
print(decrypt)
assert flag == decrypt