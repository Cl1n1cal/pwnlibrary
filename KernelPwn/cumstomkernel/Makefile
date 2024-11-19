ifeq ($(target),test)
	obj-m := test.o
else ifeq ($(target),hackme)
	obj-m := hackme.o
else
	$(error "Please specify target=test or target=hackme")
endif

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
