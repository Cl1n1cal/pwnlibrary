# Generated by kernelinit
target remote :1234
add-symbol-file vmlinux
add-symbol-file kernelinit/exploit
add-symbol-file chall.ko 0xffffffffc0000000
add-symbol-file kernelinit/kernelsymbols.o
set exception-verbose on