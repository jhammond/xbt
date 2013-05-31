
CPPFLAGS = -D_GNU_SOURCE -DX86_64 #-I/usr/include/crash
CFLAGS = -Wall -fPIC -g

all: xbt.so

xbt.so: xbt_crash.o xbt_frame_print.o xbt_eval.o
	$(CC) -shared -rdynamic -lelf -ldw $^ -o $@

dw3: dw3.o xbt_eval.o
	$(CC) -lelf -ldw $^ -o $@
