CFLAGS  = -Wall
PROGS   = rtsol rtadv ha pma mipsa
OBJS    = $(PROGS:=.o) common.o sadb.o bcache.o

all: $(PROGS)

-include $(OBJS:.o=.d)

rtsol: rtsol.o common.o
rtadv: rtadv.o common.o
ha: ha.o common.o sadb.o bcache.o
pma: pma.o common.o sadb.o
mipsa: mipsa.o common.o sadb.o

clean:
	rm *.o *.d $(PROGS) || true

%.o: %.c
	$(COMPILE.c) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) $*.c -o $*.d

.PHONY: clean
