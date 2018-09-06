from SM3 import *
import libnum
from SM4 import *
import string
import sys

f = open("rockyou.txt","rb").read().split("\n")
C = "FBF92C1A0276B443A4999F2BA8CC31703E62CC88F32B96A102DB3E9EAAA832149AD6B3B86461820600A5C22394AA064BCDEFF1BDE9961847ECBB5C78ED356014"
for i in f:
	sys.stdout.write(i+"\r")
	sys.stdout.flush()
	b = i.encode("hex")
	sm3 = SM3(b)
	c  = sm3.sm3_hash()
	flag = libnum.n2s(libnum.s2n(c[:32].decode("hex"))^libnum.s2n(c[32:].decode("hex"))).encode("hex")
	sm4 = SM4(key=flag)
	m = sm4.sm4_decrypt(C, SM4_ECB)
	cc =  m.decode("hex")
	if set(list(set(cc))+list(set(string.printable))) == set(string.printable):
		print cc
		break
	m = sm4.sm4_decrypt(C, SM4_CBC)
	cc =  m.decode("hex")
	if set(list(set(cc))+list(set(string.printable))) == set(string.printable):
		print cc
		break


#flag{keep_on_going_never_give_up_}_partial_key2_is_97712CCDDEEFF