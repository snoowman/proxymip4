CFLAGS  = -Wall
CPPFLAGS  = -Wall
LDFLAGS = -lstdc++ -lssl
PROGS   = rtadv rtsol sa ha pma
OBJS    = $(PROGS:=.o) common.o sadb.o bcache.o network.o
DESTDIR = /

all: $(PROGS)

install: all
	@for PROG in $(PROGS); \
	do \
	  cp $$PROG $(DESTDIR)/usr/sbin/pmip4-$$PROG; \
	done;

uninstall: 
	@for PROG in $(PROGS); \
	do \
	  rm $(DESTDIR)/usr/sbin/pmip4-$$PROG; \
	done;

-include $(OBJS:.o=.d)

rtadv: rtadv.o common.o
rtsol: rtsol.o common.o
sa: sa.o common.o sadb.o
ha: ha.o common.o sadb.o bcache.o network.o
pma: pma.o common.o sadb.o bcache.o network.o

clean:
	rm -f *.o *.d $(PROGS) || true

%.o: %.c
	$(COMPILE.c) $(CFLAGS) $*.c -o $*.o
	@$(CC) -MM $(CFLAGS) $*.c -o $*.d

%.o: %.cpp
	$(COMPILE.cpp) $(CFLAGS) $*.cpp -o $*.o
	@$(CC) -MM $(CFLAGS) $*.cpp -o $*.d

.PHONY: all clean
