from pwn import *
import random
import multiprocessing
import string
import itertools
import hashlib
from binascii import a2b_hex,b2a_hex
import re
from Crypto.Util.number import long_to_bytes,bytes_to_long

# context.log_level = "debug"
def generate():
    alphabet = string.ascii_letters + string.digits
    for chars in itertools.product(alphabet, repeat=4):
        yield "".join(chars)

def check(word):
    if hashlib.sha256((nonce+word).encode()).hexdigest() == target:
        return word

def PoW():
    print("[*] Running in", multiprocessing.cpu_count(), "processes...")
    pool = multiprocessing.Pool(multiprocessing.cpu_count())
    for result in pool.imap(check, generate(),10000):
        if result:
            print("[+] find: ", result)
            pool.terminate()
            pool.close()
            return result
    
def launch_attack(phi_P, Q, E, p):
    Eqp = EllipticCurve(Qp(p, 8), [ZZ(t) for t in E.a_invariants()])

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break
    p_times_Q = p * Q_Qp
    
    x_Q, y_Q = p_times_Q.xy()

    phi_Q = -(x_Q / y_Q)
    k = phi_Q / phi_P

    return ZZ(k) % p

def gen_weak_curve():
    P = 0xd3ceec4c84af8fa5f3e9af91e00cabacaaaecec3da619400e29a25abececfdc9bd678e2708a58acb1bd15370acc39c596807dab6229dca11fd3a217510258d1b  
    A = 0x95fc77eb3119991a0022168c83eee7178e6c3eeaf75e0fdf1853b8ef4cb97a9058c271ee193b8b27938a07052f918c35eccb027b0b168b4e2566b247b91dc07
    B = 7668542654793784988436499086739239442915170287346121645884096222948338279165302213440060079141960679678526016348025029558335977042712382611197995002316466
    return P, A, B

if __name__ == "__main__":
    p,a,b = gen_weak_curve()
    E = EllipticCurve(GF(p), [a, b])
    G = random.choice(E.gens())
    Eqp = EllipticCurve(Qp(p, 8), [ZZ(t) for t in E.a_invariants()])

    G_Qps = Eqp.lift_x(ZZ(G.xy()[0]), all=True)
    for G_Qp in G_Qps:
        if GF(p)(G_Qp.xy()[1]) == G.xy()[1]:
            break
            

    p_times_G = p * G_Qp

    x_G, y_G = p_times_G.xy()

    phi_G = -(x_G / y_G)
    io = remote("47.242.140.57", 9998)
    pow_line = io.recvline()
    target = pow_line[pow_line.find(b" == ")+4:-1].decode()
    nonce = pow_line[pow_line.find(b"sha256(")+7:pow_line.find(b"sha256(")+23].decode()
    assert len(target) == 64
    assert len(nonce) == 16
    io.sendlineafter(b"Give me XXXX: ",PoW())

    io.sendlineafter(b"P: ", str(p))
    io.sendlineafter(b"A: ", str(a))
    io.sendlineafter(b"B: ", str(b))
    io.sendlineafter(b"X1: ", str(G.xy()[0]))
    io.sendlineafter(b"Y1: ", str(G.xy()[1]))
    io.sendlineafter(b"X2: ", str(G.xy()[0]))
    io.sendlineafter(b"Y2: ", str(G.xy()[1]))
    for loop in range(30):
        print("[+] predicting on ", loop)
        abc = io.recvline()
        abc = abc.replace(b"(", b"")
        abc_num = [int(s) for s in abc.split() if s.isdigit()]
        Pa = E(abc_num[0], abc_num[1])
        Pb = E(abc_num[2], abc_num[3])
        Pc = E(abc_num[4], abc_num[5])
        a0 = launch_attack(phi_G, Pa, E, p)
        if a0*Pb == Pc:
            io.sendlineafter(b"Choice: ", str(0))
        else:
            io.sendlineafter(b"Choice: ", str(1))
    print(io.recvline())