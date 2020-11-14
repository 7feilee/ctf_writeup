## crypto1

```sage
from src import n1,n2,c1,c2,e1,e2

p = int(gcd(n1,n2))
q = n1/p
qq = n2/p
assert p*q == n1
assert p*qq == n2
phi1 = lcm(p-1, q-1)
phi2 = lcm(p-1, qq-1)
comm1 = int(gcd(e1,phi1))
comm2 = int(gcd(e2,phi2))
assert  comm1 == comm2
d1 = inverse_mod(int(e1/comm1), phi1)
d2 = inverse_mod(int(e2/comm2), phi2)
from Crypto.Util.number import long_to_bytes
cc1 = pow(c1,d1,n1)
cc2 = pow(c2,d2,n2)
m_146018_p = cc1%p
m_146018_q = cc1%q
m_146018_qq = cc2%qq
n3 = q*qq
cc3 = crt([int(m_146018_q),int(m_146018_qq)],[q,qq])
assert m_146018_q==cc3%q
assert m_146018_qq==cc3%qq
phi3 = lcm(q-1,qq-1)
comm3 = int(gcd(comm2, phi3))
print(f"comm3: {comm3}")
d3 = inverse_mod(int(comm2/comm3), phi3)
m_2 = int(pow(cc3, d3,int(q)*int(qq)))
P.<a> = PolynomialRing(Zmod(q), implementation='NTL')
f = a^2 - m_2
result_a = [int(i[0]) for i in f.monic().roots()]

P.<b> = PolynomialRing(Zmod(qq), implementation='NTL')
f = b^2 - m_2
result_b = [int(i[0]) for i in f.monic().roots()]
for i in result_a:
    for j in result_b:
        flag = long_to_bytes(crt([int(i),int(j)],[q,qq]))
        print(flag)
```

## crypto2

just do `bit flip` on username and last bits

## misc1

颜文字加密，[LSB with aes-cbc](https://github.com/livz/cloacked-pixel/blob/master/crypt.py) (from file description) (password is at the end of flag.zip)

aes-cbc decrypt again (48bytes -> 32bytes flag)

## misc2

`磁盘取证分析`

0. get hint by `psscan`  WinRAR.exe process. so `python ~/ctf/tools/volatility/vol.py -f becarful --profile=WinXPSP2x86 filescan |grep "zip"` -> `\Device\HarddiskVolume1\Program Files\f1@g.zip` 
1. `python ~/ctf/tools/volatility/vol.py -f becarful --profile=WinXPSP2x86 clipboard`  get password of `f1@g.zip` `good_job_guys`
2. dump file: `python ~/ctf/tools/volatility/vol.py -f becarful --profile=WinXPSP2x86 dumpfiles -D flag/ -Q 0x000000000225d800`
3. unzip the file get  a png file with vbe file appended at the end.(know that file is vbe through cmdscan and google).
4. decrypt it by `https://master.ayra.ch/vbs/vbs.aspx`
5. get decrypted vbs and run it on windows `get flag` or open vbs you will see the flag.

## re1

de4dot deobfuscator the binary and use dnSpy tools to recompile the source to  pop the flag out.