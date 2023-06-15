KDIR := /lib/modules/$(shell uname -r)/build

USRC = adblock.c tls.c http.c
TARGET_MODULE := adblock


obj-m := $(TARGET_MODULE).o
adblock-objs := kadblock.o tls.o http.o dns.o send_close.o

PWD = $(shell pwd)

all:
	./generate_hash.sh .
	gcc -o adblock $(USRC) -lnetfilter_queue

load:
	sudo insmod $(TARGET_MODULE).ko
unload:
	sudo rmmod $(TARGET_MODULE) || true >/dev/null

kernel:
	./generate_hash.sh .
	$(MAKE) unload
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	$(MAKE) load

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf adblock host_table.h .tmp*