#!/usr/bin/env sage

import os
from hashlib import sha256
from Crypto.Cipher import AES
from sage.crypto.lwe import LWE
from sage.stats.distributions.discrete_gaussian_integer import DiscreteGaussianDistributionIntegerSampler as DGDIS
from sage.modules.free_module_integer import IntegerLattice
from Crypto.Util.number import long_to_bytes
from random import randint
import sys
from itertools import starmap
from operator import mul

# From https://oddcoder.com/LOL-34c3/, https://hackmd.io/@hakatashi/B1OM7HFVI
def Babai_CVP(mat, target):
    M = IntegerLattice(mat, lll_reduce=True).reduced_basis
    G = M.gram_schmidt()[0]
    diff = target
    for i in reversed(range(G.nrows())):
        diff -=  M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
    return target - diff
# import  data
# B_copy
# M_copy
# R_copy

ct = long_to_bytes(ct)

B  = Matrix(7, 320,B_copy)
M = Matrix(64, 25, M_copy)
R = Matrix(65, 1, R_copy)

# A = random_matrix(ZZ, 320, 5, x = 10, y = 1000)
# B = Matrix(A * vector([randint(1, 2^1024) for _ in range(5)]) for _ in range(7))
# L = LWE(n = 25, q = 1000, D = DGDIS(3))
# S = [L() for _ in range(64)]
# Error = [ZZ(a.dot_product(L._LWE__s) - c) for (a,c) in S]
# M = Matrix(64, 25, [int(i).__xor__(int(j)) for i,j in zip(A.list(), (Matrix([x for x, _ in S])).list())])
# T = Matrix([randint(1, 2^1024) for _ in range(64)])
# R = T.transpose().stack(T * vector([y for _, y in S]).change_ring(ZZ))

res = B.LLL()[2:]
got = 0
out = []
for i in res:
    out.append(i)
for i in range(4):
    for j in range(i+1, 5):
            out.append(res[i]-res[j])
            out.append(res[j]-res[i])
            out.append(res[j]+res[i])
tmp = []
for i in range(3):
    for j in range(i+1, 4):
        tmp.append(res[i]-res[j])
        tmp.append(res[j]-res[i])
        tmp.append(res[j]+res[i])
        for k in range(j+1, 5):
            for idx in tmp:
                out.append(idx - res[k])
                out.append(idx + res[k])
                out.append(res[k] - idx)
count =  0
final = []
for i in  out:
    if all([10<=k<=1000 for k in i]) and i not in final:
        final.append(i)
        count+=1
nbit  = 64
T = Matrix(ZZ, nbit + 1, nbit + 1)
for i in range(nbit):
    T[i, i] = 1
for i in range(nbit):
    T[i, nbit] = R[i][0]
T[nbit, nbit] = -int(R[nbit][0])
# get y
y = T.LLL()[0][:-1]
print(len(final))
assert len(final) == 5 #so lucky just combine 3 of columns and recover A
import itertools
index = 0
b_values = y.list()

for loop in (list(itertools.permutations(final,int(5)))):
    index+=1
    AA = Matrix(loop).transpose()
    x = Matrix(64, 25, [int(i).__xor__(int(j)) for i,j in zip(AA.list(), M.list())])
    m = 64
    n = 25
    q = 1000
    A_values = x
    AAA = matrix(ZZ, m + n, m)
    for i in range(m):
        AAA[i, i] = q
    for i in range(m):
        for j in range(n):
            AAA[m + j, i] = A_values[i][j]
    target = vector(ZZ, b_values)
    res = Babai_CVP(AAA, target)
    R = IntegerModRing(q)
    MM = Matrix(R, A_values)
    ingredients = MM.solve_right(res)
    key = sha256(''.join(list(map(str, ingredients))).encode()).digest()
    iv = ct[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct[16:])
    if b"X-NUCA" in pt:
        print(pt)
# > X-NUCA{Wh4t_Tru1y_i5_l0giC?_Wh0_d3c1des_re4soN_12e8h8vbd82t4e6q}