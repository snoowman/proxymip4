CFLAGS  = -Wall
PROGS   = rtsol rtadv ha pma mipsa
OBJS    = $(PROGS:=.o) common.o sadb.o bcache.o network.o

all: $(PROGS)

-include $(OBJS:.o=.d)

rtsol: rtsol.o common.o
rtadv: rtadv.o common.o
ha: ha.o common.o sadb.o bcache.o network.o
pma: pma.o common.o sadb.o network.o
mipsa: mipsa.o common.o sadb.o

clean:
	rm *.o *.d $(PROGS) || true

%.o: %.c
	$(COMPILE.c) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) $*.c -o $*.d

%.o: %.cc
	$(COMPILE.c) $*.cc -o $*.o
	@$(CC) -MM $(CFLAGS) $*.cc -o $*.d

.PHONY: clean
