#!/bin/bash

if [ $# -ne 1 ]; then
    echo "Usage: start_chall.sh <chall_name>"
    exit 1
fi

echo "[+] Renaming to 'chall'"
mv $1 chall

echo "[+] Copying scripts"
cp ~/Desktop/pwnlibrary/scripts/xpl.py .
cp ~/Desktop/pwnlibrary/scripts/flag.txt .
cp ~/Desktop/pwnlibrary/scripts/checksec_chall.sh .

echo "[+] Running checksec_chall.sh"
./checksec_chall.sh chall

echo "[+] Removing unecessary files"
rm chall_rop_gadgets_results.txt
rm checksec_chall.sh

