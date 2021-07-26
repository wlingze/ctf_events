from pwn import * 
# context.arch='amd64'
# cn = process("./chall")

context.binary='./chall'
cn = context.binary.process()

sla = lambda a, b: cn.sendlineafter(a, b)
sa = lambda a, b: cn.sendafter(a, b)

def new(idx, name):
    sla("choice:", '0')
    sla("idx:", str(idx))
    sla("name:", name)
    
def set(idx):
    sla("choice:", '1')
    sla("idx:", str(idx))

def show():
    sla("choice:", '2')

def eat():
    sla("choice:", '3')


cn.interactive()
