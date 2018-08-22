### lovey_AES题解
正常的PKCS#7padding方案,则攻击很常规**AES-CBC Attack and bit filp**考虑IV未知,可以set IV = "00"*16,最后misc出第一块block(16bytes)的明文.
脚本采用了: https://github.com/mpgn/Padding-oracle-attack
