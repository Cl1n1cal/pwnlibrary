#!/bin/sh

# Check if a source file was provided
if [ -z "$1" ]; then
    echo "Usage: $0 <source_file>" >&2
    exit 1
fi

gcc -O0 -g -fno-inline -o exploit -static $1

# Check if gcc succeeded
if [ $? -ne 0 ]; then
    echo "Error: Compilation failed" >&2
    exit 1
fi


cp ./exploit ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../
