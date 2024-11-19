#!/bin/sh
qemu-system-x86_64 \
    -m 256M \
    -cpu kvm64,+smep,+smap \
    -kernel vmlinuz \
    -initrd initramfs.cpio.gz \
    -hdb flag.txt \
    -snapshot \
    -nographic \
    -monitor none \
    -no-reboot \
    -append "console=ttyS0 kaslr kpti=1 quiet panic=1" \
    -s

# cpu ,
# kaslr kpti=1
