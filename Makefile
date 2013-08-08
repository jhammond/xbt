
CPPFLAGS = -D_GNU_SOURCE -DX86_64
CFLAGS = -Wall -fPIC -g

all: xbt.so xbt_dwfl.so

xbt.so: xbt_crash.o xbt_frame_print.o xbt_eval.o xbt_dwarf.o
	$(CC) -shared -rdynamic -lelf -ldw $^ -o $@

xbt_dwfl.so: xbt_dwfl.o xbt_dwarf.o
	$(CC) -shared -rdynamic -lelf -ldw $^ -o $@
