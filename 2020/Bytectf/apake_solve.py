#!/usr/bin/env python3
from gmssl import sm3, func #  pip3 install gmssl
from binascii import a2b_hex, b2a_hex
from Crypto.Util.number import long_to_bytes, bytes_to_long

sm2p256v1_ecc_table = {
    'n': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
    'p': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
    'g': '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7' +
         'bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
    'a': 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
    'b': '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
}

class APAKE(object):
    def __init__(self, hashed_pwd, pk):
        self.ecc_table = sm2p256v1_ecc_table
        self.para_len = len(self.ecc_table['n'])
        self.ecc_a3 = (int(self.ecc_table['a'], base=16) + 3) % int(self.ecc_table['p'], base=16)
        self.hashed_pwd = hashed_pwd
        self.K = None
        self.public_key = pk #self._kg(int(sk, 16), self.ecc_table['g'])

    def sm3_hash_str(self, msg):
        return sm3.sm3_hash(func.bytes_to_list(msg.encode()))

    def calc_pk(self, index):        
        powG = self._kg(1 << index, self.ecc_table['g'])
        self.public_key = self._add_point(self.public_key, powG)
        self.public_key = self._convert_jacb_to_nor(self.public_key)
        return self.public_key
    
    def calc_kG(self, A):
        hpi = int(self.hashed_pwd, 16)
        n_sub_hpi = (int(self.ecc_table['n'], base=16) - hpi) % int(self.ecc_table['n'], base=16)
        n_sub_hpi_G = self._kg(n_sub_hpi, self.ecc_table['g'])
        K_sub_hpi_G = self._add_point(A, n_sub_hpi_G)
        K_sub_hpi_G = self._convert_jacb_to_nor(K_sub_hpi_G)
        return K_sub_hpi_G

    def send_client(self, kc_str):
        kc = int(kc_str, 16)
        hpi = int(self.hashed_pwd, 16)
        a = (kc + hpi) % int(self.ecc_table['n'], base=16)
        A = self._kg(a, self.ecc_table['g'])
        return A

    def calc_B(self):
        hpi = int(self.hashed_pwd, 16)
        hpi_G = self._kg(hpi, self.ecc_table['g'])
        B = self._add_point(hpi_G, self.ecc_table['g'])
        B = self._convert_jacb_to_nor(B)
        return B

    def calc_c(self, cipher, kg, index):
        self.K = kg
        enc_K = self.sm3_hash_str(self.K)
        c = int(cipher, 16) ^ int(enc_K, 16) ^ (1 << index)
        return '%064x' % c
    
    def prove_client(self, password, kc_str, A, B, c_prime):
        kc = int(kc_str, 16)
        hpi = int(self.hashed_pwd, 16)
        n_sub_hpi = (int(self.ecc_table['n'], base=16) - hpi) % int(self.ecc_table['n'], base=16)
        n_sub_hpi_G = self._kg(n_sub_hpi, self.ecc_table['g'])
        B_sub_hpi_G = self._add_point(B, n_sub_hpi_G)
        B_sub_hpi_G = self._convert_jacb_to_nor(B_sub_hpi_G)
        self.K = self._kg(kc, B_sub_hpi_G)
        enc_K = self.sm3_hash_str(self.K)
        sk = '%064x' % (int(c_prime, 16) ^ int(password, 16) ^ int(enc_K, 16))
        transcript = A + B + c_prime
        signature = self._sign(transcript, sk)
        return signature

    def _sign(self, data, sk):
        k_str = func.random_hex(len(self.ecc_table['n']))
        k = int(k_str, 16) % int(self.ecc_table['n'], base=16)
        R = self._kg(k, self.ecc_table['g'])
        x1 = R[0:self.para_len]
        e_str = self.sm3_hash_str(x1 + data)
        e = int(e_str, 16)
        d = int(sk, 16)
        s = (k - d * e) % int(self.ecc_table['n'], base=16)
        return '%064x%064x' % (s, e)

    def _verify(self, data, pk, signature):
        s = int(signature[0:self.para_len], 16)
        e = int(signature[self.para_len:2 * self.para_len], 16)
        sG = self._kg(s, self.ecc_table['g'])
        eP = self._kg(e, pk)
        R = self._add_point(sG, eP)
        R = self._convert_jacb_to_nor(R)
        x1 = R[0:self.para_len]
        e_str = self.sm3_hash_str(x1 + data)
        return e == int(e_str, 16)

    def _kg(self, k, Point):
        if (k % int(self.ecc_table['n'], base=16)) == 0:
            return '0' * 128
        Point = '%s%s' % (Point, '1')
        mask_str = '8'
        for i in range(self.para_len - 1):
            mask_str += '0'
        mask = int(mask_str, 16)
        Temp = Point
        flag = False
        for n in range(self.para_len * 4):
            if flag:
                Temp = self._double_point(Temp)
            if (k & mask) != 0:
                if flag:
                    Temp = self._add_point(Temp, Point)
                else:
                    flag = True
                    Temp = Point
            k = k << 1
        return self._convert_jacb_to_nor(Temp)

    def _double_point(self, Point):
        l = len(Point)
        len_2 = 2 * self.para_len
        if l < self.para_len * 2:
            return None
        else:
            x1 = int(Point[0:self.para_len], 16)
            y1 = int(Point[self.para_len:len_2], 16)
            if l == len_2:
                z1 = 1
            else:
                z1 = int(Point[len_2:], 16)

            T6 = (z1 * z1) % int(self.ecc_table['p'], base=16)
            T2 = (y1 * y1) % int(self.ecc_table['p'], base=16)
            T3 = (x1 + T6) % int(self.ecc_table['p'], base=16)
            T4 = (x1 - T6) % int(self.ecc_table['p'], base=16)
            T1 = (T3 * T4) % int(self.ecc_table['p'], base=16)
            T3 = (y1 * z1) % int(self.ecc_table['p'], base=16)
            T4 = (T2 * 8) % int(self.ecc_table['p'], base=16)
            T5 = (x1 * T4) % int(self.ecc_table['p'], base=16)
            T1 = (T1 * 3) % int(self.ecc_table['p'], base=16)
            T6 = (T6 * T6) % int(self.ecc_table['p'], base=16)
            T6 = (self.ecc_a3 * T6) % int(self.ecc_table['p'], base=16)
            T1 = (T1 + T6) % int(self.ecc_table['p'], base=16)
            z3 = (T3 + T3) % int(self.ecc_table['p'], base=16)
            T3 = (T1 * T1) % int(self.ecc_table['p'], base=16)
            T2 = (T2 * T4) % int(self.ecc_table['p'], base=16)
            x3 = (T3 - T5) % int(self.ecc_table['p'], base=16)

            if (T5 % 2) == 1:
                T4 = (T5 + ((T5 + int(self.ecc_table['p'], base=16)) >> 1) - T3) % int(self.ecc_table['p'], base=16)
            else:
                T4 = (T5 + (T5 >> 1) - T3) % int(self.ecc_table['p'], base=16)

            T1 = (T1 * T4) % int(self.ecc_table['p'], base=16)
            y3 = (T1 - T2) % int(self.ecc_table['p'], base=16)

            form = '%%0%dx' % self.para_len
            form = form * 3
            return form % (x3, y3, z3)

    def _add_point(self, P1, P2):
        if P1 == '0' * 128:
            return '%s%s' % (P2, '1')
        if P2 == '0' * 128:
            return '%s%s' % (P1, '1')
        len_2 = 2 * self.para_len
        l1 = len(P1)
        l2 = len(P2)
        if (l1 < len_2) or (l2 < len_2):
            return None
        else:
            X1 = int(P1[0:self.para_len], 16)
            Y1 = int(P1[self.para_len:len_2], 16)
            if l1 == len_2:
                Z1 = 1
            else:
                Z1 = int(P1[len_2:], 16)
            x2 = int(P2[0:self.para_len], 16)
            y2 = int(P2[self.para_len:len_2], 16)

            T1 = (Z1 * Z1) % int(self.ecc_table['p'], base=16)
            T2 = (y2 * Z1) % int(self.ecc_table['p'], base=16)
            T3 = (x2 * T1) % int(self.ecc_table['p'], base=16)
            T1 = (T1 * T2) % int(self.ecc_table['p'], base=16)
            T2 = (T3 - X1) % int(self.ecc_table['p'], base=16)
            T3 = (T3 + X1) % int(self.ecc_table['p'], base=16)
            T4 = (T2 * T2) % int(self.ecc_table['p'], base=16)
            T1 = (T1 - Y1) % int(self.ecc_table['p'], base=16)
            Z3 = (Z1 * T2) % int(self.ecc_table['p'], base=16)
            T2 = (T2 * T4) % int(self.ecc_table['p'], base=16)
            T3 = (T3 * T4) % int(self.ecc_table['p'], base=16)
            T5 = (T1 * T1) % int(self.ecc_table['p'], base=16)
            T4 = (X1 * T4) % int(self.ecc_table['p'], base=16)
            X3 = (T5 - T3) % int(self.ecc_table['p'], base=16)
            T2 = (Y1 * T2) % int(self.ecc_table['p'], base=16)
            T3 = (T4 - X3) % int(self.ecc_table['p'], base=16)
            T1 = (T1 * T3) % int(self.ecc_table['p'], base=16)
            Y3 = (T1 - T2) % int(self.ecc_table['p'], base=16)

            form = '%%0%dx' % self.para_len
            form = form * 3
            return form % (X3, Y3, Z3)

    def _convert_jacb_to_nor(self, Point):
        len_2 = 2 * self.para_len
        x = int(Point[0:self.para_len], 16)
        y = int(Point[self.para_len:len_2], 16)
        z = int(Point[len_2:], 16)
        z_inv = pow(z, int(self.ecc_table['p'], base=16) - 2, int(self.ecc_table['p'], base=16))
        z_invSquar = (z_inv * z_inv) % int(self.ecc_table['p'], base=16)
        z_invQube = (z_invSquar * z_inv) % int(self.ecc_table['p'], base=16)
        x_new = (x * z_invSquar) % int(self.ecc_table['p'], base=16)
        y_new = (y * z_invQube) % int(self.ecc_table['p'], base=16)
        z_new = (z * z_inv) % int(self.ecc_table['p'], base=16)
        if z_new == 1:
            form = '%%0%dx' % self.para_len
            form = form * 2
            return form % (x_new, y_new)
        else:
            return None
if __name__ == "__main__":
    from pwn import *
    loop = 256
    flag = ""
    for index in range(loop):
        io = remote("182.92.153.117", 30102)
        A = io.recvline()[4:-1].decode()
        hash_pwd = io.recvline()[7:-1].decode()
        pk = io.recvline()[12:-1].decode()
        cipher = io.recvline()[9:-1].decode()
        client = APAKE(hashed_pwd=hash_pwd, pk=pk)
        B = client.calc_B()
        kg = client.calc_kG(A)
        io.sendlineafter(b"B = ?", B)
        c = client.calc_c(cipher, kg, index)
        c_prime = io.sendlineafter(b"c_prime = ?", c)
        signature = io.recvline()[12:-1].decode()
        pk = client.calc_pk(index)
        if client._verify(A+B+c, pk, signature):
            flag +=str(((int(cipher,16) & (1 << index))>>index) ^ 0)
        else:
            flag +=str(((int(cipher,16) & (1 << index))>>index) ^ 1)
    print(long_to_bytes(int(flag[::-1],2)))