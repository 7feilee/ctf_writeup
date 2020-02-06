#! /usr/bin/python
import re
import binascii
from sys import argv, stdout
import time
from binascii import unhexlify, hexlify
from itertools import cycle, izip
from pwn import *
import libnum
import string


#context.log_level = "debug"

io = remote("117.50.10.241",10010)

io.recvuntil("Your option:")

####################################
# CUSTOM YOUR RESPONSE ORACLE HERE #
####################################
''' the function you want change to adapte the result to your problem '''
def test_validity(up_cipher):
    io.sendline("3")
    io.recvuntil("IV:")
    io.sendline(up_cipher[:32])
    io.recvuntil("Your secret:")
    io.sendline(up_cipher[32:])
    message = io.recvuntil("Your option:")
    if "Your secret is decrypted successfully but you will never know the plain text" in message:
        return 1
    else:
        return 0





# the exploit don't need to touch this part
# split the cipher in len of size_block
def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]

''' create custom block for the byte we search'''
def block_search_byte(size_block, i, pos, l):
    hex_char = hex(pos).split('0x')[1]
    return "00"*(size_block-(i+1)) + ("0" if len(hex_char)%2 != 0 else '') + hex_char + ''.join(l)    

''' create custom block for the padding'''
def block_padding(size_block, i):
    l = []
    for t in range(0,i+1):
        l.append(("0" if len(hex(i+1).split('0x')[1])%2 != 0 else '') + (hex(i+1).split('0x')[1]))
    return "00"*(size_block-(i+1)) + ''.join(l)

def hex_xor(s1,s2):
    return hexlify(''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(unhexlify(s1), cycle(unhexlify(s2)))))

def run(cipher,size_block):
    cipher       = cipher.upper()
    found        = False
    valide_value = []
    result       = []
    len_block    = size_block*2
    cipher_block = split_len(cipher, len_block)

    if len(cipher_block) == 1:
        print "[-] Abort there is only one block"
        sys.exit()  
    #for each cipher_block
    for block in reversed(range(1,len(cipher_block))):
        if len(cipher_block[block]) != len_block:
            print "[-] Abort length block doesn't match the size_block"
            break
        print "[+] Search value block : ", block, "\n"
        #for each byte of the block
        for i in range(0,size_block):
            # test each byte max 255
            for ct_pos in range(0,256):
                # 1 xor 1 = 0 or valide padding need to be checked
                if ct_pos != i+1 or (len(valide_value) > 0  and int(valide_value[-1],16) == ct_pos):

                    bk = block_search_byte(size_block, i, ct_pos, valide_value) 
                    bp = cipher_block[block-1]
                    bc = block_padding(size_block, i) 

                    tmp = hex_xor(bk,bp)
                    cb  = hex_xor(tmp,bc).upper()

                    up_cipher  = cb + cipher_block[block]
                    #time.sleep(0.5)


                    if verbose == True:
                        exe = re.findall('..',cb)
                        discover = ('').join(exe[size_block-i:size_block])
                        current =  ('').join(exe[size_block-i-1:size_block-i])
                        find_me =  ('').join(exe[:-i-1])

                        stdout.write("[+] Test [Byte %03i/256 - Block %d ]: \033[31m%s\033[33m%s\033[36m%s\033[0m\r" % (ct_pos, block, find_me, current, discover))
                        stdout.flush()

                    if test_validity(up_cipher):

                        found = True
                        
                        # data analyse and insert in rigth order
                        value = re.findall('..',bk)
                        valide_value.insert(0,value[size_block-(i+1)])

                        if verbose == True:
                            print ''
                            print "[+] Block M_Byte : %s"% bk
                            print "[+] Block C_{i-1}: %s"% bp
                            print "[+] Block Padding: %s"% bc
                            print ''

                        bytes_found = ''.join(valide_value)
                        if i == 0 and bytes_found.decode("hex") > hex(size_block) and block == len(cipher_block)-1:
                            print "[-] Error decryption failed the padding is > "+str(size_block)
                            sys.exit()

                        print '\033[36m' + '\033[1m' + "[+]" + '\033[0m' + " Found", i+1,  "bytes :", bytes_found
                        print ''

                        break 
            if found == False:
                # lets say padding is 01 for the last byte of the last block (the padding block)
                if len(cipher_block)-1 == block and i == 0:
                    value = re.findall('..',bk)
                    valide_value.insert(0,"01")
                    if args.verbose == True:
                        print ''
                        print '[-] No padding found, but maybe the padding is length 01 :)'
                        print "[+] Block M_Byte : %s"% bk
                        print "[+] Block C_{i-1}: %s"% bp
                        print "[+] Block Padding: %s"% bc
                        print ''
                        bytes_found = ''.join(valide_value)
                else:
                    print "\n[-] Error decryption failed"
                    result.insert(0, ''.join(valide_value))
                    hex_r = ''.join(result)
                    print "[+] Partial Decrypted value (HEX):", hex_r.upper()
                    padding = int(hex_r[len(hex_r)-2:len(hex_r)],16)
                    print "[+] Partial Decrypted value (ASCII):", hex_r[0:-(padding*2)].decode("hex")
                    sys.exit()
            found = False

        result.insert(0, ''.join(valide_value))
        valide_value = []

    print ''
    hex_r = ''.join(result)
    print "[+] Decrypted value (HEX):", hex_r.upper()
    padding = int(hex_r[len(hex_r)-2:len(hex_r)],16)
    print "[+] Decrypted value (ASCII):", hex_r[0:-(padding*2)].decode("hex")

if __name__ == '__main__':
    verbose = True
    #set IV = "00"*16                     
    cipher = "00"*16+"4d63406edd37fd21ebe26fab684d3c85d6e72a892012a83f258e42985f28b47dc6b70cc02f05b9027c23d0018c40fc33"
    run(cipher, 16)
'''

[+] Decrypted value (HEX): 353F323428033237373A3D340C3C2132636C6526466C69707065645F426974737D0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F
[+] Decrypted value (ASCII): 5?24(\x03277:=4\x0c<!2cle&Flipped_Bits}
-> the first block of the message should xor with IV now it is time to guess IV
"53535353535353535353535353535353" ->  flag{Padding_oracle&Flipped_Bits}

[+] Block M_Byte : 666c61677b50616464696e675f6f7261
[+] Block C_{i-1}: 53535353535353535353535353535353
[+] Block Padding: 10101010101010101010101010101010

[+] Found 16 bytes : 666c61677b50616464696e675f6f7261


[+] Decrypted value (HEX): 666C61677B50616464696E675F6F7261636C6526466C69707065645F426974737D0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F
[+] Decrypted value (ASCII): flag{Padding_oracle&Flipped_Bits}
[*] Closed connection to 117.50.10.241 port 10010
'''
