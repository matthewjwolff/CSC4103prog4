all:
	make crack

clean:
	rm crack

crack: crack.c
	gcc -o crack crack.c -lcrypt -pthread
