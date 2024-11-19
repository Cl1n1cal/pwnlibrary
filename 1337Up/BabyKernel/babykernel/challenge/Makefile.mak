# Set the object file for your module
obj-m := hackme.o

# Path to the kernel build directory
KDIR := /lib/modules/$(shell uname -r)/build

# Current directory where Makefile is located
PWD := $(shell pwd)

# Default target
all:
	make -C $(KDIR) M=$(PWD) modules

# Clean target
clean:
	make -C $(KDIR) M=$(PWD) clean
