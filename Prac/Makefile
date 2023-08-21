CC=gcc
STRIP=/usr/bin/strip
CFLAGS=-Wall
LDFLAGS=

all: PacketEye

argdump.o: argdump.c hexdump.h
	     $(CC) -c $(CFLAGS) argdump.c

hexdump.o: hexdump.c hexdump.h
	     $(CC) -c $(CFLAGS) hexdump.c

PacketEye: argdump.o hexdump.o
	   $(CC) -o PacketEye argdump.o hexdump.o $(LDFLAGS)
	   $(STRIP) PacketEye

.PHONY: clean

clean:
	rm -rf PacketEye argdump.o hexdump.o

