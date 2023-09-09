CC=gcc
STRIP=/usr/bin/strip
CFLAGS=-Wall
LDFLAGS=

all: PacketEye

argdump.o: argdump.c hexdump.h icmpRead.h arpRead.h
	     $(CC) -c $(CFLAGS) argdump.c

hexdump.o: hexdump.c hexdump.h
	     $(CC) -c $(CFLAGS) hexdump.c
	     
icmpRead.o: icmpRead.c icmpRead.h
	     $(CC) -c $(CFLAGS) icmpRead.c
	     
arpRead.o: arpRead.c arpRead.h
	     $(CC) -c $(CFLAGS) arpRead.c

PacketEye: argdump.o hexdump.o icmpRead.o arpRead.o
	   $(CC) -o PacketEye argdump.o hexdump.o icmpRead.o arpRead.o $(LDFLAGS)
	   $(STRIP) PacketEye

.PHONY: clean

clean:
	rm -rf PacketEye argdump.o hexdump.o icmpRead.o arpRead.o

