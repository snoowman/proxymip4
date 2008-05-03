CFLAGS  = -Wall
LDFLAGS = -lstdc++
PROGS   = rtadv rtsol mipsa ha pma
OBJS    = $(PROGS:=.o) common.o sadb.o bcache.o network.o

all: $(PROGS)

-include $(OBJS:.o=.d)

rtadv: rtadv.o common.o
rtsol: rtsol.o common.o
mipsa: mipsa.o common.o sadb.o
ha: ha.o common.o sadb.o bcache.o network.o
pma: pma.o common.o sadb.o network.o

clean:
	rm -f *.o *.d $(PROGS) || true

%.o: %.c
	$(COMPILE.c) $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) $*.c -o $*.d

%.o: %.cpp
	$(COMPILE.cpp) $(CFLAGS) $*.cpp -o $*.o
	@$(CC) -MM $(CFLAGS) $*.cpp -o $*.d

.PHONY: clean
