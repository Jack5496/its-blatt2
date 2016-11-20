default-target: all

all: sniffer

debug: sniffer.o.debug
 gcc sniffer.o -o sniffer
 gcc -static -g -o sniffer sniffer.c
 rm -rf sniffer.o

sniffer: sniffer.o
 gcc sniffer.o -o sniffer
 rm -rf sniffer.o

sniffer.o: sniffer.c
 gcc -D_GNU_SOURCE -c -Wall -pedantic sniffer.c

sniffer.o.debug: sniffer.c
 gcc -O0 -D_GNU_SOURCE -c -Wall -pedantic sniffer.c

clean:
 rm -rf sniffer sniffer.o log.txt
