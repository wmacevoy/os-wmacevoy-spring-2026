CFLAGS = -Wall -Wextra -g -std=c11

all : drunken-sailor

run : all
	nice ./drunken-sailor --steps=1 --prob-left=0.2 --prob-middle=0.2 --prob-right=0.6
	
drunken-sailor : drunken-sailor.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean :
	rm -f drunken-sailor

.PHONY : clean