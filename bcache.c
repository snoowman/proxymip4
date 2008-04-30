#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <netinet/in.h>
#include "bcache.h"

struct binding *bcache = NULL;

int add_binding(struct binding *b)
{
	b->next = bcache;
	bcache = b;
	// TODO allocate tunnel here
	return 0;
}

int remove_binding(struct binding *b)
{
	struct binding *p = bcache;
	struct binding *prev = NULL;

	while (p) {
		if (p == b)
			break;
		p = p->next;
	}

	if (!p)
		return 1;
	if (prev == NULL)
		bcache = p->next;
	else
		prev->next = p->next;
	free(p);
	// TODO deallocate tunnel here
	return 0;
}

struct binding *find_binding(in_addr_t hoa)
{
	struct binding *p = bcache;
	while (p) {
		if (p->hoa == hoa)
			return p;
		p = p->next;
	}
	return NULL;
}

void list_binding()
{
	struct binding *p = bcache;
	printf("binding cache\n");
	while (p) {
		printf("  hoa:%08x ha:%08x coa:%08x lastid:%016llx",
			p->hoa, p->ha, p->coa, p->lastid);
		if (p->timeout == 0)
			printf(" infinite\n");
		else
			printf(" %lu (s)\n", p->timeout - time(NULL));
		p = p->next;
	}
	printf("\n");
}
