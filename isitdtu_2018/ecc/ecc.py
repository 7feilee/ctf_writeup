from random import randint
from sys import argv, stdout

from fastecdsa.curve import P256
from fastecdsa.point import Point
from mathutil import p256_mod_sqrt, mod_inv

VERBOSE = True

def gen_point():
    P = P256.G  
    d = randint(2, P256.q)  
    e = mod_inv(d, P256.q)  
    Q = e * P 
    assert(d * Q == P)    
    return P, Q, d

def find_point_on_p256(x):
    # equation: y^2 = x^3-ax+b
    y2 = (x * x * x) - (3 * x) + P256.b
    y2 = y2 % P256.p
    y = p256_mod_sqrt(y2)
    return y2 == (y * y) % P256.p, y

def gen_prediction(observed, Q, d):
    checkbits = observed & 0xffff

    for high_bits in range(2**16):
        guess = (high_bits << (8 * 30)) | (observed >> (8 * 2))
        on_curve, y = find_point_on_p256(guess)

        if on_curve:
            # use the backdoor to guess the next 30 bytes
            # point = Point(p256.curve, guess, y)
            point = Point(guess, y, curve=P256)
            s = (d * point).x
            r = (s * Q).x & (2**(8 * 30) - 1)

            if VERBOSE:
                stdout.write('Checking: %x (%x vs %x)   \r' %
                             (high_bits, checkbits, (r >> (8 * 28))))
                stdout.flush()

            # check the first 2 bytes against the observed bytes
            if checkbits == (r >> (8 * 28)):
                if VERBOSE:
                    stdout.write('\r\n')
                    stdout.flush()

                # if we have a match then we know the next 28 bits
                return r & (2**(8 * 28) - 1)

    return 0

class gen_ECC():
    def __init__(self, seed, P, Q):
        self.seed = seed
        self.P = P
        self.Q = Q

    def genbits(self):
        t = self.seed
        s = (t * self.P).x
        self.seed = s
        r = (s * self.Q).x
        return r & (2**(8 * 30) - 1)  # return 30 bytes

def main():
    # P, Q, d = gen_point()
    P = Point(0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296, 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5, curve=P256)
    Q = Point(0x43595b13c9dc2e7e6fdc09175a5527c4973778d96a9e602fc5bf35d7f8f43424, 0xda93baf3284401b5426dea5354e63738817ff4938f9532157ccff8535f6d1076, curve=P256)
    d = 0xe7366b3509adb3de385d04712f8556c1cca77ee91d7e7df1fcfbd902c127d744

    e = gen_ECC(20639247711360085, P, Q)
    focus = 0x56929a811a2ac18732371d1615c937d92c61204481c746c9f836febf862b6096
    predicted = gen_prediction(focus, Q, d)
    print "[+]predicted:",hex(predicted),predicted
    # tmp = e.genbits()
    # secret = e.genbits()
    # print secret
    # _flag = secret & (2**(8*28) - 1)
    # # flag is ISITDTU{15286070551713753818008772789796636300551465225304565454416856095491} with _flag is int
    # focus = (tmp << (2 * 8)) | (secret >> (28 * 8))
    # print focus
    # 0x56929a811a2ac18732371d1615c937d92c61204481c746c9f836febf862b6096


if __name__ == '__main__':
    main()
