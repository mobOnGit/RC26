CC = gcc
CFLAGS = -Wall -Wextra -g

all: user

user: user.c
	$(CC) $(CFLAGS) -o user user.c

clean:
	rm -f user *.o

.PHONY: all clean