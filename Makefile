
CPPFLAGS = -D_GNU_SOURCE -DX86_64 #-I/usr/include/crash
CFLAGS = -Wall -fPIC

all: xbt.so dw dw1 dw2 dw3

xbt.so: xbt.o
	$(CC) -shared -rdynamic -lelf -ldw $^ -o $@

dw: dw.o
	$(CC) -lelf -ldw $^ -o $@

dw1: dw1.o
	$(CC) -lelf -ldw $^ -o $@

dw2: dw2.o
	$(CC) -lelf -ldw $^ -o $@

dw3: dw3.o
	$(CC) -lelf -ldw $^ -o $@

# xbt.so:
# 	gcc -Wall -D_GNU_SOURCE -I/usr/include/crash -shared -rdynamic -o xmod.so xmod.c -fPIC -DX86_64
