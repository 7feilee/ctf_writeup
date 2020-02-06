# -*-coding:utf-8-*-
'''
Created on 2016-4-7

@author: 014731
'''

from common import *
'''
IV：初始值，用于确定压缩函数寄存器的初态
'''
IV = (0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e)

'''
T(j)：常量，随j的变化取不同的值
'''
T0_15 = 0x79cc4519
T16_63= 0x7a879d8a

'''
SM3支持的消息最大比特长度
'''
SM3_MSG_MAX_BITS = 2 << 63

'''
FF(j)：布尔函数，随j的变化取不同的表达式
GG(j)：布尔函数，随j的变化取不同的表达式
'''
def _ff_0_15(x, y, z):
    '''
    FF(j)：布尔函数  0<=j<=15
    '''
    if is_word(x) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % x) 
    if is_word(y) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % y)
    if is_word(z) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % z)
    
    return x ^ y ^ z

def _ff_16_63(x, y, z):
    '''
    FF(j)：布尔函数  16<=j<=63
    '''
    if is_word(x) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % x) 
    if is_word(y) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % y)
    if is_word(z) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % z)
    
    return (x & y)|(x & z)|(y & z)

def _gg_0_15(x, y, z):
    '''
    GG(j)：布尔函数  0<=j<=15
    '''
    if is_word(x) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % x) 
    if is_word(y) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % y)
    if is_word(z) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % z)
    
    return x ^ y ^ z

def _gg_16_63(x, y, z):
    '''
    GG(j)：布尔函数  16<=j<=63
    '''
    if is_word(x) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % x) 
    if is_word(y) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % y)
    if is_word(z) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % z)
    
    return (x & y)|((~x) & z)


def _p0_conv(x):
    '''
    P0：压缩函数中的置换函数
    '''
    if is_word(x) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % x)
    
    return x ^ lrotate(x, 9) ^ lrotate(x, 17)

def _p1_conv(x):
    '''
    P1：压缩函数中的置换函数
    '''
    if is_word(x) == False: 
        raise Exception('源数据[%X]不在word定义范围[0x00000000 - 0xFFFFFFFF]，不能进行变换计算' % x)
    
    return x ^ lrotate(x, 15) ^ lrotate(x, 23)  

def _sm3_message_pad(message):
    '''
    假设消息m 的长度为L比特。首先将比特'1'添加到消息的末尾，再添加k 个'0'，k是满
    足L + 1 + k与448 mod 512 同余((L+1+k) mod 512 = 448 % 512) 的最小的非负整数。然后再添加一个64位比特串，该比特串是长度L的二进
    制表示。填充后的消息m′的比特长度为512的倍数。
    '''
    if len(message) % 2 != 0: 
        raise Exception('待填充数据长度[%s]错误,需要为2的整倍数' % len(message))
         
    if IsHexCharacter(message) == False: 
        raise Exception('待填充数据含有非法字符(非16进制字符)')

    len_bits = len(message) * 4
    '''  
    搜寻k值
    '''
    k = 7
    while True:
        if (len_bits + 1 + k) % 512 == 448 % 512:
            break
        else:
            k += 8
    '''
    填充1个'1',再填充k个'0'
    '''
    padmsg = message + '80'
    out_format = '%%0%dX' % ((k-7)/4)
    padmsg += out_format % 0x00
    
    '''
    填充长度
    '''
    padmsg += '%016X' % len_bits
    
    if (len(padmsg) * 4) % 512 != 0:
        raise Exception('填充后数据长度[%d]错误， 必须为512整数倍' % len(padmsg))
    
    return (padmsg, len(padmsg) * 4)

class SM3(object):
    '''
    SM3密码杂凑算法
    '''
    def __init__(self, srcmsg = '00'):
        self.message, self.length = _sm3_message_pad(srcmsg)
    
    def __str__(self):
        return 'SM3 object :\nmessage : %s\nlength  : %d bits\n' % (self.message, self.length)
    
    def _cf_process(self, iv, message_group):
        '''
        CF压缩函数
        iv : int
        message_group : hexstring
        '''
        try:
            W, WE = self._message_extend(message_group)
        except Exception, e:
            raise Exception(e)
        '''
        for num in W:
            print '%08X' % num
        for num in WE:
            print '%08X' % num
        '''
        A = iv[0]
        B = iv[1]
        C = iv[2]
        D = iv[3]
        E = iv[4]
        F = iv[5]
        G = iv[6]
        H = iv[7]
        
#      print '迭代压缩中间值:\n j     A        B        C        D        E        F        G        H    '
#        print 'iv %08X %08X %08X %08X %08X %08X %08X %08X' % (A,B,C,D,E,F,G,H)
        
        for i in xrange(0, 63 + 1):
            if 0 <= i <= 15:
                SS1 = lrotate((lrotate(A, 12) + E + lrotate(T0_15, i))%(2<<31), 7)
            else:
                if i <= 32:
                    SS1 = lrotate((lrotate(A, 12) + E + lrotate(T16_63, i))%(2<<31), 7)
                else:
                    SS1 = lrotate((lrotate(A, 12) + E + lrotate(T16_63, abs(32 - i)))%(2<<31), 7)
            
            SS2 = SS1 ^ lrotate(A, 12)
            
            if 0 <= i <= 15:
                TT1 = (_ff_0_15(A, B, C) + D + SS2 + WE[i])%(2<<31)
                TT2 = (_gg_0_15(E, F, G) + H + SS1 + W[i])%(2<<31)
            else:
                if i == 16:
                    pass
                TT1 = (_ff_16_63(A, B, C) + D + SS2 + WE[i])%(2<<31)
                TT2 = (_gg_16_63(E, F, G) + H + SS1 + W[i])%(2<<31)
            
            D = C
            C = lrotate(B, 9)
            B = A
            A = TT1
            H = G
            G = lrotate(F, 19)
            F = E
            E = _p0_conv(TT2)
#			print '%02d %08X %08X %08X %08X %08X %08X %08X %08X' % (i, A,B,C,D,E,F,G,H)
            
        return (A^iv[0], B^iv[1], C^iv[2], D^iv[3], E^iv[4], F^iv[5], G^iv[6], H^iv[7])
       
    def _message_extend(self, message_group):
        '''
        W(j)生成, 消息扩展, 返回 (W, WE)
        '''
        if IsHexCharacter(message_group) == False:
            raise Exception('分组消息含有非法字符(非16进制字符)')
        
        if len(message_group) % 16 != 0:
            raise Exception('用于扩展的分组消息长度[%d]错误' % len(message_group))
        
        W  = []
        WE = []
        '''
        W0 - W15
        '''
        position = 0
        while True:
            W.append(int(message_group[position:position + 8], 16))
            position += 8
            if len(message_group) == position:
                break
        
        '''
        W16 - W67
        '''
        for i in xrange(16, 67 + 1):
            rspP1 = _p1_conv(W[i - 16] ^ W[i - 9] ^ lrotate(W[i - 3], 15))
            W.append(rspP1 ^ lrotate(W[i - 13], 7) ^ W[i - 6])
        
        '''
        WE0 - WE63
        '''
        for i in xrange(0, 63 + 1):
            WE.append(W[i] ^ W[i+4])
        
        return (W, WE)
    
    def sm3_hash(self):
        '''
        SM3 计算杂凑值
        '''
        n = self.length / 512
        position = 0
        v = []
        v.append(IV)
        for i in xrange(0, n):
            v.append(self._cf_process(v[i], self.message[position: position + 128]))
            
            position += 128
            if len(self.message) == position:
                break
        return '%08X%08X%08X%08X%08X%08X%08X%08X' % (v[len(v)-1])
        
#---------------------------------------------------------------------------------------------
if __name__ == '__main__':
    message = 'ab'
    sm3 = SM3(message)
    print sm3.__str__()
    print '\nHASH: %s'  % sm3.sm3_hash()
    print '-'*120
    message = '04D24163C411A9D03A3B77A082B29064CAD7A3FA737C13667D6F67760D9C86A984A0A1DDEAFD0A8C4B5F7223EA64D5CFB70BD29F4AC33FB343069DC4E499E8D354649444570F02F46319B5927DE7E09210FEEFDA4D5847BC4204B159D45517040B1C6A'
    sm3 = SM3(message)
    print sm3.__str__()
    print '\nHASH: %s'  % sm3.sm3_hash()
    print '-'*120