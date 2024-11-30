#!/bin/bash

# Parse command line args
if [[ "$#" -ne 1 ]]; then
    echo "[!] Error: checksec_chall.sh"
    echo "[!] usage ./checksec_chall <chall_name>"
    exit 1
fi

echo "[+] Starting checksec_chall.sh"

pwn checksec $1 > results.txt 2>&1 # overwrite existing

grep -q "NX enabled" results.txt

if [ $? -ne 0 ]; then
    echo "[+] Copying shellcode.txt"
    cp ~/Desktop/pwnlibrary/scripts/shellcode.txt .
    echo "Shellcode is 24 bytes" >> results.txt
    cat shellcode.txt >> results.txt
fi

ROPgadget --binary $1 > chall_rop_gadgets.txt # overwrite existing

if [ $? -eq 0 ]; then
    echo "[+] Parsing ROP gadgets"
    cp ~/Desktop/pwnlibrary/scripts/parse_gadgets.py .
    python3 parse_gadgets.py chall_rop_gadgets.txt
    cat chall_rop_gadgets_results.txt >> results.txt
fi

if [ $? -ne 0 ]; then
    echo "[!] Error: checksec_chall.sh"
    echo "[!] Parsing ROP gadgets failed"
    exit 1
else
    echo "[+] Parsing ROP gadgets success"
fi

echo "[+] Opening results.txt"
cat results.txt

echo "[+] Checksec_chall.sh finished!"
    