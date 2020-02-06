#!/usr/bin/python

from pwn import *
import sys
from base64 import b64encode,b64decode
from hashpumpy import hashpump
from binascii import unhexlify,hexlify
import time
#context.log_level = "debug"
# for some easy last points on RCTF

def perform_hlext(tag, orig_msg, append_msg, keylen):
    newdgst, newmsg = hashpump(tag,orig_msg,append_msg,keylen)
    return newdgst,newmsg

# p = remote("117.50.9.136",10011)
# p.recvuntil("Please input your identifier, leave blank and i will give you a new one :")
# p.sendline()
# p.recvuntil("First,Please input your name:")
# p.sendline("7feilee")
# p.recvuntil("Please input your option :")

# BSiZUpdZ3GK/HIyo5q3DacRAZ4vcneIsMMjkO7ZLeKmaCUIdqPWHgdPZxMMD7ZFkK05qRlFRflNbPiFnako5dg==
# own=""&name=7feilee&money=100
for i in range(109,0,-1):
    p = remote("117.50.9.136",10011)
    p.recvuntil("Please input your identifier, leave blank and i will give you a new one :")
    p.sendline()
    p.recvuntil("First,Please input your name:")
    p.sendline("7feilee")
    p.recvuntil("Please input your option :")
    print "Trying length extension of %d" % i
    p.sendline("1")
    data = p.recvuntil("Please input your identifier, leave blank and i will give you a new one :")
    signature = data.split("Your newest identifier is :")[1].split("\n")[1]
    '''
    wpUDOZQfgiO008SsyxlCtxLjPCLSzN6XokmG2peetDkY8SqeAUz+Oo5sawhqsuAZbHZl7ZXOQn3+4fDw/HfpUF08RFNnNEwoQ1cMImlAbAE=
    SsyxlCtxLjPCLSzN6XokmG2peetDkY8SqeAUz+Oo5sawhqsuAZbHZl7ZXOQn3+4fDw/HfpUF08RFNnNEwoQ1cMImlAbAE=
    {"own": ["1", "_", "1"], "name": "7feilee", "money": 80}
    This is what you have : 
    1 瓜子	前排必备
    1 瓜子	前排必备
    '''
    newdata = b64decode("wpUDOZQfgiO008SsyxlCtxLjPCLSzN6XokmG2peetDkY8SqeAUz+Oo5sawhqsuAZbHZl7ZXOQn3+4fDw/HfpUF08RFNnNEwoQ1cMImlAbAE=")[:-1]+chr(i)
    p.sendline(b64encode(newdata))
    print b64encode(newdata)
    print "Trying length extension of %d" % i
    sleep(1)
    fuck = p.recv()
    fuck += p.recv()
    print fuck
    if '["1", "4", "1"]' in fuck:
        exit()
    p.close()
    #flag{flipped_bit_to_forge_data}