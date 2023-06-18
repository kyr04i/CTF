#!/usr/bin/env python3

from pwn import *
import time
import sys

local = 0
debug = 0

# context.arch = 'amd64'
# context.endian = 'little'
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
		s = process('chall')
		if debug:
			gdb.attach(s, gdbscript='''
			''')
		else:
			raw_input('DEBUG')
	else:
          s = remote('localhost', 1234)
 
	return s

s = conn()

def sz_choice():
	s.sendlineafter(b'> ', str(choice).encode())

'''
Main menu:
1. Create new page
2. Edit page
3. Unload page from memory storage
4. Write all memory storage to backend
5. Check page for target
6. Exit
'''

def create(num_identify):
    s.sendlineafter(b'> ', b'1')
    s.sendlineafter(b'> ', str(num_identify).encode())

# edit 
'''
1. Get number of elements in page
2. Add element to page
3. Read element in page
4. Edit element in page
5. Execute element in page
6. Go back to main menu
'''
def edit(num_identify, n_edit):
    s.sendlineafter(b'> ', b'2')
    s.sendlineafter(b'> ', str(num_identify).encode())
    

def unload():
    s.sendlineafter(b' >', b'3')
    
def write_memo():
    s.sendlineafter(b'> ', b'4')
    
def check_page(num_identify):
    s.sendlineafter(b'> ', b'5')
    s.sendlineafter(b'> ', str(num_identify.encode()))
    return s.recvline()
    


s.interactive()


