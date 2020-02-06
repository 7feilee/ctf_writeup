#!/usr/bin/env python
from os import urandom

def ksa(key):
    permS = []
    for x in range(256):
        permS.append(x)
    j = 0
    for x in range(256):
        j = (j+permS[x]+ord(key[x%len(key)]))%256
        temp = permS[x]
        permS[x] = permS[j]
        permS[j] = temp
    return permS
def prga(S, length):
    x = 0
    y = 0
    keystream = []
    for z in range(length):
        x = (x+1)%256
        y = (y+S[x])%256
        temp = S[x]
        S[x] = S[y]
        S[y] = temp
        keystream.append(S[(S[x]+S[y])%256])
    return keystream
analysis = {}
key_len = 16
for i in range(0,100000):
    key = urandom(key_len)
    tS = ksa(key)
    out = prga(tS, key_len)
    ct = out[1]
    if not ct in analysis:
        analysis[ct] = 1
    else:analysis[ct] = analysis[ct]+1
print sorted(analysis.items(),key = lambda item:item[1])