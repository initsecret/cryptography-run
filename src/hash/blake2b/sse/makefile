CC=gcc
CFLAGS=-O3 -I../testvectors -Wall -Wextra -std=c89 -pedantic -Wno-long-long
BLAKEBINS=blake2s blake2b blake2sp blake2bp blake2xs blake2xb

all:		$(BLAKEBINS) check

blake2b:	blake2b.c
		$(CC) blake2b.c -o $@ $(CFLAGS) -DBLAKE2B_SELFTEST

check:          blake2s blake2b blake2sp blake2bp blake2xs blake2xb
	        ./blake2s
	        ./blake2b
	        ./blake2sp
	        ./blake2bp
	        ./blake2xs
	        ./blake2xb

kat:
		$(CC) $(CFLAGS) -o genkat-c genkat-c.c blake2b.c blake2s.c blake2sp.c blake2bp.c blake2xs.c blake2xb.c
		$(CC) $(CFLAGS) -g -o genkat-json genkat-json.c blake2b.c blake2s.c blake2sp.c blake2bp.c blake2xs.c blake2xb.c
		./genkat-c > blake2-kat.h
		./genkat-json > blake2-kat.json

clean:
		rm -rf *.o genkat-c genkat-json blake2-kat.h blake2-kat.json $(BLAKEBINS)
