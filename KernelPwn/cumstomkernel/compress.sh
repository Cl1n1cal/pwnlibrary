#!/bin/sh
gcc -o exploit -static $1

# Check if gcc compiled successfully
if [ $? -ne 0 ]; then
  echo "Compilation failed. Exiting."
  exit 1
else
  echo "Compilation successful."
fi

mv ./exploit ./initramfs
cd initramfs
find . -print0 \
| cpio --null -ov --format=newc \
| gzip -9 > initramfs.cpio.gz
mv ./initramfs.cpio.gz ../
