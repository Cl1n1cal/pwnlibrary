#!/bin/bash
qemu-system-x86_64 \
    -m 128M \
    -kernel bzImage \
    -initrd initramfs.cpio \
    -append "console=ttyS0 loglevel=3 oops=panic panic=1 pti=off kaslr quiet" \
    -cpu qemu64,+smep \
    -monitor /dev/null \
    -nographic \
    -no-reboot -s