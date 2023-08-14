CC = gcc
CFLAGS = -Wall -Wextra

all: encrypt decrypt

program: encrypt.c
	$(CC) $(CFLAGS) -o encrypt encrypt.c

program: decrypt.c
	$(CC) $(CFLAGS) -o decrypt decrypt.c

clean:
	rm -f encrypt decrypt
