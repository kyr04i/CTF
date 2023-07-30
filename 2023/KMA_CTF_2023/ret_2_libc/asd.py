#!/usr/bin/env python3

from pwn import *
from ctypes import *
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
		s = process('./chall')
		if debug:
			gdb.attach(s, gdbscript='''
            b* 0x0000000000401958
            continue
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('188.166.220.129', 10001)

	return s

s = conn()

# nc 103.162.14.240 15001
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
# libc = ELF('./libc.so.6)


 
