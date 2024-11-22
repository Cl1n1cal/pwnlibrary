#!/bin/bash
if [ "$1" == "protection" ]; then
    qemu-system-x86_64 \
        -m 256M \
        -kernel bzImage \
        -initrd initramfs.cpio.gz \
        -append "console=ttyS0 oops=panic panic=1 quiet loglevel=3 kpti=off kaslr" \
        -nographic \
        -no-reboot \
        -monitor /dev/null
elif [ "$1" == "debug" ]; then
    qemu-system-x86_64 \
        -m 256M \
        -kernel bzImage \
        -initrd initramfs.cpio.gz \
        -append "console=ttyS0 oops=panic panic=1 quiet loglevel=3 nokaslr nosmep nosmap nopti" \
        -nographic \
        -no-reboot \
        -monitor /dev/null \
        -s

else
    qemu-system-x86_64 \
        -m 256M \
        -kernel bzImage \
        -initrd initramfs.cpio.gz \
        -append "console=ttyS0 oops=panic panic=1 quiet loglevel=3 nokaslr nosmep nosmap nopti" \
        -nographic \
        -no-reboot \
        -monitor /dev/null
fi
