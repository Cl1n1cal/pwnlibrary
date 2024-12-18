#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("chal_patched")

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


io.interactive()
