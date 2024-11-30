#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("chall_patched")

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
def register(age: int, name: bytes, description: bytes):
    io.sendline(b"1")
    io.sendlineafter(b"hacker? ", str(age).encode())
    io.sendlineafter(b"name ? ", data)
    io.sendlineafter(b"hacker ? ", description)
    io.recvuntil(b">> ")


io = start()

register(0, b"A"*16, b"B"*32)
register(0, b"A"*16, b"B"*32)
register(0, b"A"*16, b"B"*32)




io.interactive()
