SUBDIRS = src contrib

all:
	@for DIR in $(SUBDIRS); \
	do $(MAKE) -C $$DIR $@; \
	done

clean:
	@for DIR in $(SUBDIRS); \
	do $(MAKE) -C $$DIR $@; \
	done

install:
	$(MAKE) -C src $@

uninstall:
	$(MAKE) -C src $@

.PHONY: all clean
