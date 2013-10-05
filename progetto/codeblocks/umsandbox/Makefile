GCCFLAGS= -Wall -Wunused -pedantic
LINKERFLAGS=

all: clean test
	
test: test.o utils.o
	gcc ${GCCFLAGS} -shared -o libumsandbox.so test.o utils.o

clean:
	rm -f libumsandbox.so
	sudo rm -f /usr/local/lib/umview/modules/umsandbox.so

utils.o: utils.c
	gcc -c ${GCCFLAGS} utils.c

test.o: test.c utils.h
	gcc -c -shared ${GCCFLAGS} test.c

install:
	mv libumsandbox.so /usr/local/lib/umview/modules/umsandbox.so
