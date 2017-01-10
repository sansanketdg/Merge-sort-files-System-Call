obj-m += sys_xmergesort.o

INC=/lib/modules/$(shell uname -r)/build/arch/x86/include

all: xhw1 mergesort

xhw1: xhw1.c
	gcc -Wall -Werror -I$(INC)/generated/uapi -I$(INC)/uapi xhw1.c -o xmergesort

mergesort:
	make -Wall -Werror -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f xmergesort
