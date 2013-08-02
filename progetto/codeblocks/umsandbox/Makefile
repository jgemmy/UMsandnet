all:
	make clean
	gcc -shared -o bin/Debug/libumsandbox.so test.c

clean:
	rm -f bin/Debug/libumsandbox.so
	sudo rm -f /usr/local/lib/umview/modules/umsandbox.so

install:
	sudo mv bin/Debug/libumsandbox.so /usr/local/lib/umview/modules/umsandbox.so
