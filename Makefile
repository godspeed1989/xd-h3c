CC=gcc
BIN=xdh3c
OBJS=xd_h3c.o authenticate.o
CFLAGS=-lpcap -lgcrypt
INSTALL=install
RM=rm

$(BIN): xd_h3c.o authenticate.o
	$(CC) $(CFLAGS) $(OBJS) -o $@

xd_h3c.o: xd_h3c.c
	$(CC) $(CFLAGS) -c $<

authenticate.o: authenticate.c authenticate.h
	$(CC) $(CFLAGS) -c $<

install:
	$(INSTALL) -d /usr/local/bin
	$(INSTALL) -p -D -m 0755 $(BIN) /usr/local/bin

uninstall:
	$(RM) -rf /usr/local/bin/$(BIN)

clean:
	@$(RM) -rf $(OBJS) $(BIN)

