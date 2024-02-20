#compiler and flags
CC = gcc
CFLAGS = -Wall -g

#src file and output name
SRC = dhcp-stats.c
OUT = dhcp-stats

#libraries
LIBS = -lpcap -lncurses -lm

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) -o $(OUT) $(SRC) $(LIBS)

clean:
	rm -f $(OUT)