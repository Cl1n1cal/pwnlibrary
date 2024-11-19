#!/bin/bash
if [ "$1" == "NOPROT" ]; then
    qemu-system-x86_64 \
        -m 256M \
        -kernel bzImage \
        -initrd initramfs.cpio.gz \
        -append "console=ttyS0 oops=panic panic=1 quiet loglevel=3 kaslr=off kpti=off nopti selinux=0 security=none apparmor=0 noaslr" \
        -nographic \
        -no-reboot \
        -monitor /dev/null
else
    qemu-system-x86_64 \
        -m 256M \
        -kernel bzImage \
        -initrd initramfs.cpio.gz \
        -append "console=ttyS0 oops=panic panic=1 quiet loglevel=3 kpti=off kaslr" \
        -nographic \
        -no-reboot \
        -monitor /dev/null
fi
