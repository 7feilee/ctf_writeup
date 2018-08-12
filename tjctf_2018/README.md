#tjctf 2018
- [crypto](#crypto)
	- [Permutations](#permutations)
## crypto
###Permutations
This is a normal RC4, we can send 10 bytes mask "abcdefghij"   permutations to the server, and the server will map the mask to message and then encrypt the message every time with RC4 and urandom(16) keys.
the task file:
```python
#!/usr/bin/env python3
from os import urandom
from itertools import permutations

def ksa(key):
    permS = []
    for x in range(256):
        permS.append(x)
    j = 0
    for x in range(256):
        j = (j+permS[x]+key[x%16])%256
        temp = permS[x]
        permS[x] = permS[j]
        permS[j] = temp
    return permS
def prga(S, mes):
    x = 0
    y = 0
    mes = bytearray(mes, "utf_8")
    cipher = ""
    stream = bytearray()
    for z in range(len(mes)):
        x = (x+1)%256
        y = (y+S[x])%256
        temp = S[x]
        S[x] = S[y]
        S[y] = temp
        stream.append(S[(S[x]+S[y])%256])
        op = str(hex(mes[z]^stream[z]))
        if len(op)%2 != 0:
            cipher += "0"+op[2:]
        else:
            cipher += op[2:]
    return cipher
mask = "abcdefghij"
message = xxxxxxxxxx
mestomask = {}
masktomes = {}
for x in range(len(mask)):
    mestomask[message[x]] = mask[x]
    masktomes[mask[x]] = message[x]
def change(maskmes):
    out=""
    for x in maskmes:
        out += masktomes[x]
    return out
    
while True:
    print("Enter a permutation of abcdefghij and I'll encrypt the corresponding message! ")
    i = input()
    if len(i) == len(mask) and  set(i) == set(mask):
        em = change(i)
        key = urandom(16)
        tS = ksa(key)
        ct = prga(tS, em)
        print(ct)
```
analysis RC4, we can find the only thing that counts is KSA function, which generates a 256 sequence based on the key, the smallest operation is byte. So we can analysis the every position of the keystream. Base on analysis, the first byte is random generate keystream.  So we take a look at the second byte of the keysteam.
from the result of analysis_rc4.py the second byte more like to be 0x00, So we can query many times on the same permutation("abcdefghij") to get the ciphertext (down.py) and count the most often byte in the second position, this the message[1] , and repeat to get all message.
```python
data = open("fix10","rb").read().split("\n")
out = {}
for i in data:
    if not out.has_key(i[2:4]):
        out[i[2:4]] = 1
    else:out[i[2:4]]+=1
print sorted(out.items(),key = lambda item:item[1])
#message:ohbyteRC4!
#tjctf{ohbyteRC4!}
```
flag:tjctf{ohbyteRC4!}