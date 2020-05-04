from sage.all import *
from pwn import *
import multiprocessing
import string
import itertools
import hashlib
from binascii import a2b_hex,b2a_hex
from Crypto.Util.number import long_to_bytes,bytes_to_long

context.log_level = "debug"
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

def backdoor(secret):
    io.sendline("Backdoor")
    io.sendlineafter("Give me the secret:\n",(str(secret)))

def exchange(x,y):
    if count !=0:
        io.sendline("Exchange")
    io.sendlineafter("X:\n", str(x))
    io.sendlineafter("Y:\n", str(y))
    io.sendline("Encrypt")
    io.sendlineafter("Give me your message(hex):\n", "f"*128)
    io.recvuntil("The result is:\n")
    data = io.recvuntil("\n").split(b"\n")[0]
    pointcompress = int.from_bytes(a2b_hex(data),"big")
    ex,ey = (pointcompress>>256)&(2**256-1)^(2**256-1),pointcompress&(2**256-1)^(2**256-1)
    return ex,ey

def main_loop():
    global count
    count = 0
    p =  0xdd7860f2c4afe6d96059766ddd2b52f7bb1ab0fce779a36f723d50339ab25bbd
    a =  0x4cee8d95bb3f64db7d53b078ba3a904557425e2a6d91c5dfbf4c564a3f3619fa

    quotients, mods = [], []
    factors = [[17, 2311817], [ 443], [11, 47, 1327481], [37, 59, 71337711241], [2333, 5657, 287038167079], [178933314029, 31721990265529, 10656972007187707], [23, 499],[1103], [96789257], [10903, 10713047],[43],[719, 80599],[31, 19813513],[3, 1968625373111472113],[103, 853, 1567, 20731],[11, 119653],[],[],[112327, 141811]]
    for i in [2, 3, 4, 5, 8, 9,10,11,12,14,15,18]:
        b = i
        try:
            E = EllipticCurve(GF(p), [a, b])
            order = E.order()
            for prime in factors[i]:
                if prime > 10 and prime < 2**32 and prime not in mods:
                    try:
                        print("Solving for prime", prime)
                        G = E.gen(0) * int(order / prime) # if cost time too much we change other b for other ecc.
                        G1x, G1y = exchange(G**[**0], G[1])
                        count+=1
                        G1 = E(G1x, G1y)
                        solution = G.discrete_log(G1)
                        print("K mod " + str(prime) + " = " + str(solution))
                        mods.append(prime)
                        quotients.append(solution)
                        print('Known relations', quotients, mods)
                    except Exception as e:
                        print(e)
                        pass # wrong point
        except Exception as e:
            print(e)
            pass # wrong curve
    secret = CRT_list(quotients, mods)
    print(secret)
    print('Secret', secret%p)
    backdoor(secret%p)
    backdoor(secret%p)

if __name__ == "__main__":
    io = remote("134.175.225.42", 8848)
    data = io.recvuntil("\n")
    target = data[data.find(b" == ") + 4 : data.find(b"\n")].decode()
    nonce = data[data.find(b"+") + 1 : data.find(b")")].decode()
    s =  pow()
    io.sendlineafter("Give me XXXX:",s)
    main_loop()