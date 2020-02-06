#!/usr/bin/env python2
#flag format DrgnS{...}
import SocketServer
import socket
from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from struct import pack, unpack
from sys import argv, stdout
import time
import copy

io = remote("aes-128-tsb.hackable.software",1337)
# io = remote("127.0.0.1",1337)
# context.log_level = "debug"

#useful function
def split_by(data, step):
    return [data[i : i+step] for i in xrange(0, len(data), step)]


def xor(a, b):
    assert len(a) == len(b)
    return ''.join([chr(ord(ai)^ord(bi)) for ai, bi in zip(a,b)])


def pad(msg):
    byte = 16 - len(msg) % 16
    return msg + chr(byte) * byte


def unpad(msg):
    if not msg:
        return ''
    return msg[:-ord(msg[-1])]


def once(size_a,a,size_b,b):
    io.send(size_a)
    io.send(a)
    io.send(size_b)
    io.send(b)
once(p32(0),"",p32(0),"")
size = unpack('<I', io.recv(4))[0]
data = io.recv(size)
data = bytearray(data)

#test get the last char of the padded plaintext

collect_xor = []
block = split_by(data,16)
print repr("".join(str(i) for i in block))
modify_bk = split_by(data,16)
target = "gimme_flag"
for loop in range(0,len(target)):
    print "working on \033[31m%s\033[0m"%(target[loop])
    for xx in range(0,256):
        # print xx
        flag = 0
        for a in [13]:
            stdout.write("[+] Test [Byte %03i/256 - Byte %03i/256] \r\n\r" % (xx,a))
            # stdout.flush()
            for index in range(len(modify_bk)):
                if index==0:
                    modify_bk[index][-1] = chr(a^(63-loop)^block[index][-1])
                    modify_bk[index][loop] = chr(xx^block[index][loop])
                else:
                    modify_bk[index][-1]=chr(block[index-1][-1]^block[index][-1]^modify_bk[index-1][-1])
                    modify_bk[index][loop]=chr(block[index-1][loop]^block[index][loop]^modify_bk[index-1][loop])
            modify = "".join(str(i) for i in modify_bk)
            once(p32(loop+1),target[:loop+1],p32(size),modify)
            check_size = unpack('<I', io.recv(4))[0]
            check_data = io.recv(check_size)
            if 'Looks like you don\'t know the secret key? Too bad.' not in check_data:
                print repr(modify)
                print repr("".join(str(i) for i in block))
                for index in range(len(block)):
                    if index==0:
                        block[index][loop] = chr(xx^block[index][loop])
                    else:
                        block[index][loop]=chr(block[index-1][loop]^block[index][loop]^modify_bk[index-1][loop])
                print repr("".join(str(i) for i in block))
                flag = 1
                break
                
        if flag:
            break
print repr("".join(str(i) for i in block))


            






