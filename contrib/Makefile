CFLAGS    = -Wall -I../src
CPPFLAGS  = -Wall -I../src
LDFLAGS = -lstdc++
PROGS   = iflog gratarp unarp homecn
OBJS    = $(PROGS:=.o)

all: $(PROGS)

clean:
	rm -f *.o *.d $(PROGS) || true

.PHONY: all clean
