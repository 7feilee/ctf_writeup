#! /usr/bin/env sage
from secret import FLAG

class DGK(object):
    def __init__(self, nbits, lbits):
        self.nbits = nbits
        self.lbits = 2 * lbits
        self.pubkey, self.prikey = self.keygen()
        self.n, self.u, self.g, self.h = self.pubkey
        self.vp, self.vq, self.p, self.q = self.prikey
        
    def keygen(self):
        vpq_bits = 80
        vp = random_prime(2**vpq_bits,False,2**(vpq_bits-1))
        vq = random_prime(2**vpq_bits,False,2**(vpq_bits-1))
        u = 1 << self.lbits
        
        r1bits = self.nbits / 2 - vpq_bits - self.lbits
        flag = 0
        while not flag:
            r1 = random_prime(2**r1bits,False,2**(r1bits-1))
            p = (u*vp*r1) + 1
            flag = is_prime(p)
            
        r2bits = self.nbits / 2 - vpq_bits - 1 - self.lbits
        flag = 0
        while not flag:
            r2 = random_prime(2**r2bits,False,2**(r2bits-1))
            q = (u*vq*r2) + 1
            flag = is_prime(q)
        
        n = p * q
        
        xp = randint(0, p)
        
        e1 = (u >> 1) * vp * r1
        e2 = u * vp
        e3 = u * r1
        
        while not (pow(xp, e1, p)!=1 and pow(xp, e2, p)!=1 and pow(xp, e3, p)!=1):
            xp = randint(0, p)
            
        xq = randint(0, q)
        e1 = (u >> 1) * vq * r2
        e2 = u * vq
        e3 = u * r2
    
        while not (pow(xq, e1, q)!=1 and pow(xq, e2, q)!=1 and pow(xq, e3, q)!=1):
            xq = randint(0, q)

        qinv = inverse_mod(q, p)
        pinv = inverse_mod(p, q)
        g = (qinv * q * xp + pinv * p * xq) % n
        g = pow(g, r1*r2, n)
        h = pow(g, r1*r2*u, n)
        
        tmp1 = pow(g, vp, p)
        tmp2 = u - 1

        self.pow_2 = [1<<i for i in range(self.lbits)]
        self.pow_pg = [pow(pow(tmp1, i, p), tmp2, p) for i in self.pow_2]
        return (n, u, g, h), (vp, vq, p, q)

    def encrypt(self, pt):
        assert int(pt).bit_length() <= self.lbits
        r = randint(0, 2**400)
        r = pow(self.h, r, self.n)
        ct = pow(self.g, pt, self.n)
        ct = Integer((ct * r) % self.n)
        return ct
            
    def decrypt(self, ct):
        y = pow(ct, self.vp, self.p)
        pt = 0
        for i in range(self.lbits):
            yi = pow(y, self.pow_2[self.lbits - 1 - i], self.p)
            if yi != 1:
                pt = pt + self.pow_2[i]
                y = (y * self.pow_pg[i]) % self.p
        return pt

def decrypt(ct, g, vp, p, lbits):
    lbits = 2 * lbits
    u = 1 << lbits
    tmp1 = pow(g, vp, p)
    tmp2 = u - 1

    pow_2 = [1<<i for i in range(lbits)]
    pow_pg = [pow(pow(tmp1, i, p), tmp2, p) for i in pow_2]
    y = pow(ct, vp, p)
    pt = 0
    for i in range(lbits):
        yi = pow(y, pow_2[lbits - 1 - i], p)
        if yi != 1:
            pt = pt + pow_2[i]
            y = (y * pow_pg[i]) % p
    return pt
if __name__ == "__main__":
    from Crypto.Util.number import bytes_to_long, long_to_bytes
    assert len(FLAG)  == 72
    dgk = DGK(1024, 32)
    chunks, chunk_size = len(FLAG), 8
    flag_num = [bytes_to_long(FLAG[i:i+chunk_size]) for i in range(0, chunks, chunk_size)]
    cts = [dgk.encrypt(i) for i in flag_num]
    encs = []
    acc = 1
    for ct in cts:
        acc = (acc * ct) % dgk.n
        encs.append(acc)
        
    vp, vq, p, q = dgk.prikey
    with open("public.txt", "w+") as f:
        f.write(str(dgk.pubkey))
    with open("hint.txt", "w+") as f:
        f.write(str(vp*vq) + "\n")
        f.write(str((p+q)>>100))
    with open("encs.txt", "w") as f:
        f.write(str(encs))
        
    with open("public.txt", "r") as f:
        n,u,g,h = literal_eval(f.read())
    with open("hint.txt", "r") as f:
        vpvq ,p_add_q = map(int, f.read().split("\n"))
    with open("encs.txt", "r") as f:
        encs = literal_eval(f.read())

    p_add_q = p_add_q << 100
    p_pro = (p_add_q + int(sqrt(p_add_q * p_add_q - 4 * n))) // 2
    F.<x> = PolynomialRing(Zmod(n), implementation='NTL')
    poly = p_pro + x
    x0 = poly.small_roots(X = 2 ** 100, beta = 0.11, epsilon = 0.5)
    if x0:
        p = int(gcd(p_pro+x0[0],n))
        q = n//int(p)
    assert p*q == n
    vp = gcd(p-1, vpvq)
    vq = gcd(q-1, vpvq)

    pre = 0
    flag = b""
    for i in encs:
        pts = decrypt(i, g, vp, p, 32)
        flag+=long_to_bytes((pts-pre)%2**64)
        pre = pts
    print(flag)