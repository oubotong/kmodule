CONFIG_MODULE_SIG=n
obj-m += pprotect.o
all:
	#make -C /home/botong/sev-mintcb/linux-sev-mintcb M=$(PWD) modules
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	#make -C /home/botong/sev-mintcb/linux-sev-mintcb M=$(PWD) clean
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
