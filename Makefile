
CPPFLAGS = -D_GNU_SOURCE -DX86_64 #-I/usr/include/crash
CFLAGS = -Wall -fPIC

all: xbt.so

xbt.so: xbt.o
	$(CC) -shared -rdynamic -lelf $^ -o $@

# xbt.so:
# 	gcc -Wall -D_GNU_SOURCE -I/usr/include/crash -shared -rdynamic -o xmod.so xmod.c -fPIC -DX86_64
