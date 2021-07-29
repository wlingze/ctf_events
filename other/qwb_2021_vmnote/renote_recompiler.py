from pwn import *

class vmnote:
    def __init__(self, filename):
        self.regs = ["rdi", "rsi", "rdx", "rcx",  "r8", "r9", "r10", "r11", "r12","r13", "r14", "rbp", "rsp"]
        self.set_opcode(filename)
        self.handlers_init()
        self.stack = []
        self.eflag = 0
        self.asmcode = ""

    def set_opcode(self, filename):
        f = open(filename, "rb")
        self.opcode_size = u32(f.read(4))
        data_size = u32(f.read(4))
        self.pc = u32(f.read(4))
        self.pdata = u32(f.read(4))
        self.opcode = f.read(self.opcode_size)
        self.data = f.read(data_size)

    def string_decode(self, index, var):
        arr = []
        xor = 0
        i = 0;
        while True:
            xor = (self.data[index + i]-i) ^ var
            if xor==0:
                break;
            arr.append(xor)
            i += 1
        return bytes(arr), hex(index)


    def recompile(self, filename):
        buf = self.asmcode
        code = asm(buf, arch='amd64')
        open(filename, "wb").write(code)

    def get_reg(self):
        return self.regs[self.fetch()]

    def fetch(self, flag=1):
        if flag == 1:
            self.pc += 1
            var = self.opcode[self.pc - 1]
        if flag == 2:
            self.pc += 2
            var = u16(self.opcode[self.pc - 2:self.pc])
        if flag == 3:
            self.pc += 4
            var = u32(self.opcode[self.pc - 4:self.pc])
        if flag == 4:
            self.pc += 8
            var = u64(self.opcode[self.pc - 8:self.pc])
        return var

    def type(self, flag):
        '''
        if flag==1:
            return "byte ptr"
        if flag==2:
            return "word ptr"
        if flag==3:
            return "dword ptr"
        if flag==4:
            return "qword ptr"
        '''
        return ""

    def get_data(self, flag, index):
        idx = index - self.pdata
        if flag == 1:
            var = self.data[idx]
        if flag == 2:
            var = u16(self.data[idx:idx + 2])
        if flag == 3:
            var = u32(self.data[idx:idx + 4])
        if flag == 4:
            var = u64(self.data[idx:idx + 8])
        return var

    def disasm(self):
        self.is_run = 1
        while ((self.pc < self.opcode_size) and (self.is_run)):
            var = self.fetch()
            op = var & 0x1f
            flag = (var >> 5) & 7

            self.asmcode += "_{:04x}:\t".format(self.pc - 1)
            if (op > 0x1d):
                print("no! op > 0x1d")
            else:
                self.handlers[op](flag)

    def loop(self, string):
        self.asmcode += "_{:04x}:\t mov rax, {};\nret;\n".format(self.pc, self.pc, string, self.pc)
        self.pc += 1;

    # push
    def push(self, flag):
        self.asmcode += " push {}\n".format(self.get_reg())

    # mov reg, data[reg, flag]
    def mov_ptr(self, flag):
        reg1 = self.get_reg()
        reg2 = self.get_reg()
        # print case 1
        # print("mov {}, {}data[{}]".format(self.get_reg(), self.type(flag), self.get_reg()))
        self.asmcode += "mov {}, {}[{}]\n".format(reg1, self.type(flag), reg2)

    def handler02(self, flag):
        print("1111")

    def input(self, flag):
        reg1 = self.get_reg()
        self.asmcode += "call _0777\n"

    def leave(self, flag):
        self.asmcode += "leave\n"

    # sub reg, {reg/numbe}
    def sub(self, flag):
        reg1 = self.get_reg()
        if flag:
            number = self.fetch(flag)
            self.asmcode += "sub {}, 0x{:08x}\n".format(reg1, number)
        else:
            reg2 = self.get_reg()
            self.asmcode += "sub {}, {}\n".format(reg1, reg2)

    def handler06(self, flag):
        print("1111")

    def add(self, flag):
        reg1 = self.get_reg()
        if flag:
            number = self.fetch(flag)
            self.asmcode += "add {}, 0x{:08x}\n".format(reg1, number)
        else:
            reg2 = self.get_reg()
            self.asmcode += "add {}, {}\n".format(reg1, reg2)

    def handler08(self, flag):
        print("1111")

    # mov data[reg2, flag], reg1
    def mov_store(self, flag):
        reg1 = self.get_reg()
        reg2 = self.get_reg()
        # print case 1
        self.asmcode += "mov {}[{}], {}\n".format(self.type(flag), reg2, reg1)

    def handler0a(self, flag):
        print("1111")

    # cmp reg1, {reg2/number}
    def cmp(self, flag):
        reg1 = self.get_reg()
        if flag:
            number = self.fetch(4)
            self.asmcode += "cmp {}, 0x{:08x}\n".format(reg1, number)
        else:
            reg2 = self.get_reg()
            self.asmcode += "cmp {}, {}\n".format(reg1, reg2)

    def exit(self, flag):
        self.asmcode += "call _0774 # exit\n"
        self.is_run = 0

    # and reg1, {reg2/number}
    def andd(self, flag):
        reg1 = self.get_reg()
        if flag:
            number = self.fetch(flag)
            self.asmcode += "and {}, 0x{:08x}\n".format(reg1, number)
        else:
            reg2 = self.get_reg()
            self.asmcode += "and {}, {}\n".format(reg1, reg2)

    def handler0e(self, flag):
        print("1111")

    def handler0f(self, flag):
        print("1111")

    def handler10(self, flag):
        print("1111")

    # call {number/reg}
    def call(self, flag):
        if flag:
            target = self.fetch(3)
            self.asmcode += "call _{:04x}\nmov rdi, rax\n".format(target)
            # self.pc = target
        else:
            self.asmcode += "call {}\nmov rdi, rax\n".format(self.get_reg())

    def inc(self, flag):
        reg1 = self.get_reg()
        self.asmcode += "inc {}\n".format(reg1)

    def jmp(self, flag):
        target = self.fetch(3)
        if flag == 0:
            self.asmcode += "jmp _{:04x}\n".format(target)
        if flag == 1:
            self.asmcode += "jz _{:04x}\n".format(target)
        if flag == 2:
            self.asmcode += "jnz _{:04x}\n".format(target)
        if flag == 3:
            self.asmcode += "jl _{:04x}\n".format(target)
        if flag == 4:
            self.asmcode += "jg _{:04x}\n".format(target)

    def pop(self, flag):
        reg = self.get_reg()
        self.asmcode += "pop {}\n".format(reg)

    def handler15(self, flag):
        print("1111")

    # mov reg, {number/reg}
    def mov1(self, flag):
        if flag:
            reg = self.get_reg()
            number = self.fetch(flag)
            self.asmcode += "mov {}, 0x{:08x}\n".format(reg, number)
        else:
            reg1 = self.get_reg()
            reg2 = self.get_reg()
            self.asmcode += "mov {}, {}\n".format(reg1, reg2)

    def print(self, flag):
        reg1 = self.get_reg()
        if flag == 0:
            self.asmcode += "call _0775\n\t\tmov rdi, rax\n"
        if flag == 1:
            self.asmcode += "call _0776\n\t\tmov rdi, rax\n"

    def ret(self, flag):
        self.asmcode += "mov rax, rdi\n\t\tret\n\n"

    def syscall(self, flag):
        self.asmcode += "mov rax, rdi\n\t\tsyscall\n"

    def handler1a(self, flag):
        print("1111")

    def test(self, flag):
        self.asmcode += "test {}, {}\n".format(self.get_reg(), self.get_reg())

    def mul(self, flag):
        if flag:
            reg1 = self.get_reg()
            number = self.fetch(flag)
            # print("mul {}, 0x{:08x}".format(reg1, number))
            self.asmcode += """
            mov rax, {}; 
            mov rbx, {}
            mul rbx;
            mov {}, rax
            """.format(reg1, number, reg1)

    # xor reg, {reg/number}
    def xor(self, flag):
        if flag:
            reg1 = self.get_reg()
            number = self.fetch(flag)
            self.asmcode += "xor {}, 0x{:08x}\n".format(reg1, number)
        else:
            reg1 = self.get_reg()
            reg2 = self.get_reg()
            self.asmcode += "xor {}, {}\n".format(reg1, reg2)

    def handlers_init(self):
        self.handlers = {
            0x00: self.push,
            0x01: self.mov_ptr,
            0x02: self.handler02,
            0x03: self.input,
            0x04: self.leave,
            0x05: self.sub,
            0x06: self.handler06,
            0x07: self.add,
            0x08: self.handler08,
            0x09: self.mov_store,
            0x0a: self.handler0a,
            0x0b: self.cmp,
            0x0c: self.exit,
            0x0d: self.andd,
            0x0e: self.handler0e,
            0x0f: self.handler0f,
            0x10: self.handler10,
            0x11: self.call,
            0x12: self.inc,
            0x13: self.jmp,
            0x14: self.pop,
            0x15: self.handler15,
            0x16: self.mov1,
            0x17: self.print,
            0x18: self.ret,
            0x19: self.syscall,
            0x1a: self.handler1a,
            0x1b: self.test,
            0x1c: self.mul,
            0x1d: self.xor,
        }


def dis():
    vm = vmnote("./note.bin")
    vm.disasm()
    vm.loop("exit")
    vm.loop("print0")
    vm.loop("print1")
    vm.loop("input")
    print(vm.asmcode)
    print(vm.data)
    # vm.recompile("recom.bin")
    print(vm.string_decode(0, 137))
    print(vm.string_decode(0xc, 66))
    print(vm.string_decode(0x18, 36))
    print(vm.string_decode(0x132, 71))
    print(vm.string_decode(0x173, 17))
    print(vm.string_decode(0x182, 17))
    print(vm.string_decode(0x18d, 17))

    check = vm.data[0x120:0x120+17]
    data = vm.data[0x1f:]
    arr = []
    for i in range(17):
        arr.append(data.find(check[i]))
    print(bytes(arr))


if __name__ == '__main__':
    dis()
