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
        vpq_bits = 160
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

        return (n, u, g, h), (vp, vq, p, q)

    def encrypt(self, pt):
        assert int(pt).bit_length() <= self.lbits
        r = randint(0, 2**400)
        r = pow(self.h, r, self.n)
        ct = pow(self.g, pt, self.n)
        ct = Integer((ct * r) % self.n)
        return ct
            
    
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