all:
	make clean
	gcc -shared -o umsandbox.so umsandbox.c

clean:
	rm -f umsandbox.so
	sudo rm -f /usr/local/lib/umview/modules/umsandbox.so

install:
	sudo mv umsandbox.so /usr/local/lib/umview/modules/umsandbox.so
