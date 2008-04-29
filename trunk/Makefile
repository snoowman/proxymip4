CFLAGS=-Wall

all: rtsol rtadv ha pma

ha: ha.o common.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

ha.o: ha.c common.h
	$(CC) $(CFLAGS) -c -o $@ $<

pma: pma.o common.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

pma.o: pma.c common.h
	$(CC) $(CFLAGS) -c -o $@ $<

rtsol: rtsol.o common.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

rtsol.o: rtsol.c common.h
	$(CC) $(CFLAGS) -c -o $@ $<

rtadv: rtadv.o common.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

rtadv.o: rtadv.c common.h
	$(CC) $(CFLAGS) -c -o $@ $<

common.o: common.c common.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm *.o rtsol rtadv ha pma || true

.PHONY: clean
