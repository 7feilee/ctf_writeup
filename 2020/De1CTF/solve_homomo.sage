from sage.all import *
from pwn import *
import multiprocessing
import string
import itertools
import hashlib
from binascii import a2b_hex,b2a_hex
from Crypto.Util.number import long_to_bytes,bytes_to_long
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler
import os,random,sys,string

# assert(len(flag) == 44)
# context.log_level = "debug"

q = 2^54
t = 2^8
d = 2^10
delta = int(q/t)
PR.<x> = PolynomialRing(ZZ)
DG = DiscreteGaussianDistributionIntegerSampler(sigma=1)
fx = x^d + 1
Q.<X> = PR.quotient(fx)

def sample(r):
    return Q([randint(0,r) for _ in range(d)])

def genError():
    return Q([DG() for _ in range(d)])

def Round(a,r):
    A = a.list()
    for i in range(len(A)):
        A[i] = (A[i]%r) - r if (A[i]%r) > r/2 else A[i]%r
    return Q(A)

def round_normal(a,r):
    A = a
    for i in range(len(A)):
        A[i] = (A[i]%r) - r if (A[i]%r) > r/2 else A[i]%r
    return A

def genKeys():
    s = sample(1)
    a = Round(sample(q-1),q)
    e = Round(genError(),q)
    pk = [Round(-(a*s+e),q),a]
    return s,pk

def encrypt(m):
    u = sample(1)
    e1 = genError()
    e2 = genError()
    c1 = Round(pk[0]*u + e1 + delta*m,q)
    c2 = Round(pk[1]*u + e2,q)
    return (c1.list(),c2.list())

def decrypt(c):
    c0 = Q([i for i in c[0]])
    c1 = Q([i for i in c[1]])
    data = (t * Round(c0 + c1*s,q)).list()
    for i in range(len(data)):
        data[i] = round(data[i]/q)
    data = Round(Q(data),t)
    return data

def add(c1,c2):
    return (round_normal(c1[0]+c2[0],q),round_normal(c1[1]+c2[1],q))

def generate():
    alphabet = string.ascii_letters + string.digits
    for chars in itertools.product(alphabet, repeat=4):
        yield "".join(chars)

def check(word):
    if hashlib.sha256((word + nonce).encode()).hexdigest() == target:
        return word

def pow():
    assert len(target) == 64
    assert len(nonce) == 16
    print("Running in", multiprocessing.cpu_count(), "processes...")

    pool = multiprocessing.Pool(multiprocessing.cpu_count())
    for result in pool.imap(check, generate(),10000):
        if result:
            print(result)
            pool.terminate()
            pool.close()
            return result

def enczero():
    io.sendline("Encrypt")
    io.sendlineafter("Please input your data:\n","\x00")
    io.recvuntil("The result is: \n")
    data = io.recvuntil("\n")
    enc_zero = eval(data[:data.find(b"\n")])[0]
    return enc_zero

def dec(c):
    c0 = str(c[0]).replace("[","").replace("]","")
    c1 = str(c[1]).replace("[","").replace("]","")
    io.sendline("Decrypt")
    io.sendlineafter("Please input c0(Separated by commas):\n", c0)
    io.sendlineafter("Please input c1(Separated by commas):\n", c1)
    io.sendlineafter("The index:\n", str(0))
    io.recvuntil("The result is: \n")
    flag_bytes = chr(eval(io.recvuntil("\n").split(b"\n")[0]))
    return flag_bytes

if __name__ == "__main__":
    io = remote("106.52.135.150", 8848)
    data = io.recvuntil("\n")
    target = data[data.find(b" == ") + 4 : data.find(b"\n")].decode()
    nonce = data[data.find(b"+") + 1 : data.find(b")")].decode()
    s =  pow()
    io.sendlineafter("Give me XXXX:",s)
    io.recvuntil("The enc flag is: \n")
    cipher = []
    for i in range(44):
        tmp = []
        for j in range(2):
            tmp.append(eval(io.recvuntil("\n").split(b"\n")[0]))
        cipher.append(tmp)
    enc_zero = enczero()
    flag_enc = []
    for i in cipher:
        flag_enc.append(add(i,enc_zero))
    flag = ""
    for c in flag_enc:
        flag+=dec(c)
        print(flag)