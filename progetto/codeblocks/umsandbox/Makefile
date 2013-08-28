all:
	make clean
	gcc -shared -o libumsandbox.so test.c

clean:
	rm -f libumsandbox.so
	sudo rm -f /usr/local/lib/umview/modules/umsandbox.so

install:
	mv libumsandbox.so /usr/local/lib/umview/modules/umsandbox.so
