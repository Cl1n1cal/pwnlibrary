#!/usr/bin/python3
from pwn import *

# initialize the binary
binary = "./spaceman"
elf = context.binary = ELF(binary, checksec=False)
qemu = ELF('./qemu-riscv64',checksec=False)

gs = """
b *main
"""

if args.REMOTE:
    p = remote("challs.pwnoh.io", 13372)
elif args.GDB:
    p = qemu.process(['-g','1234',binary])
    print("Remote debugging started...")
    gdb.attach(("127.0.0.1",1234), gdbscript=gs, exe=binary)
else:
    p = qemu.process([binary])


# Plan:

# Addresses

# Functions


p.interactive()
