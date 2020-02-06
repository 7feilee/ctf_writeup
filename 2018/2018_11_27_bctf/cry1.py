# -*- coding: utf-8 -*-

from pwn import *

context.log_level = "debug"

base = 1<<120
io = remote("39.96.8.114",9999)
for i in range(10):
    io.recvuntil("Please input your number to guess the coeff: ")
    io.sendline(str(base))
    io.recvuntil("This is the sum: ")
    sum = int(io.recvuntil("\n").strip())
    print sum
    xx = []
    while sum/base!=0:
        xx.append(sum%base)
        sum=sum/base
    xx.append(sum)
    io.recvuntil("It is your time to guess the coeff!")
    data = " ".join(str(coff) for coff in xx[::-1])
    io.sendline(data)
io.recv()



