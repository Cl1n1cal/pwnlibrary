#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("flaminglips")
libc = ELF("./libc.so.6")

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
def new(index, size, data):
    io.sendline(b"1")
    io.sendlineafter(b"> ",f"{index}".encode())
    io.sendlineafter(b"> ",f"{size}".encode())
    io.sendlineafter(b"> ",f"{data}".encode())
    io.recvuntil(b"> ")

io = start()

io.recvuntil(b"Heap leak: ")
heap = int(io.recvline(), 16)

new(0, 20, "AAAA")


io.interactive()
