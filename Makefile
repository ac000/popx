CC=gcc
CFLAGS=-Wall -g -std=c99 -pedantic -O2 -fstack-protector-strong -fPIC -Wl,-z,now -pie

popx: popx.c
	 $(CC) $(CFLAGS) -o popx popx.c

clean:
	rm -f popx
