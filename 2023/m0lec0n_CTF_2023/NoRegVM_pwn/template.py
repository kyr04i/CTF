#!/usr/bin/env python3
from pwn import *

r = remote("0.0.0.0", 3333)
r = process('./challenge')
elf = context.binary = ELF('./challenge')

code_file = open("challenge.vm", "rb")
r.send(code_file.read()+b'ENDOFTHEFILE')
code_file.close()
memory_file = open("strings.vm", "rb")
r.send(memory_file.read()+b'ENDOFTHEFILE')
memory_file.close()
r.recvuntil(b"Starting challenge...\n")


r.interactive()
