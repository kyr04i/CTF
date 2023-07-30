from pwn import *

io =process('./chall2')

elf = context.binary = ELF('./chall2')

gdb.attach(io)
pause()

io.interactive()
