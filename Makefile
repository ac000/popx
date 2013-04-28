CC=gcc
CFLAGS=-Wall -g -std=c99 -O2
LDFLAGS=

popx: popx.c
	 $(CC) $(CFLAGS) -o popx popx.c

clean:
	rm -f popx
