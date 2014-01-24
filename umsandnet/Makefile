GCCFLAGS= -Wall -Wunused
LINKERFLAGS=

all: umsandnet
	
umsandnet: umsandnet.o
	gcc ${GCCFLAGS} -shared -o umsandnet.so umsandnet.o

clean:
	rm -f umsandnet.so umsandnet.o
	sudo rm -f /usr/local/lib/umview/modules/umsandnet.so

umsandnet.o: umsandnet.c
	gcc -c -shared ${GCCFLAGS} umsandnet.c

install:
	cp umsandnet.so /usr/local/lib/umview/modules/umsandnet.so
