CC = gcc
LIBS = -lm
CFLAGS = -ansi -pedantic-errors -Wall -Werror -g

all: md5main

md5.o: md5.c
md5main.o: md5main.c

md5main: md5.o md5main.o
	$(CC) $+ $(LIBS) -o $@

clean:
	rm -rf *.o md5main

