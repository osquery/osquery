obj-m += camb.o
camb-objs += main.o hash.o sysfs.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
