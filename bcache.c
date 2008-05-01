#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <net/if.h>
#include <netinet/in.h>
#include "bcache.h"
#include "network.h"

struct binding *bcache = NULL;

int add_binding(struct binding *b)
{
	b->next = bcache;
	bcache = b;

	// TODO allocate tunnel here
	char tif[IFNAMSIZ];
	tunnel_name(tif, IFNAMSIZ, b->coa);
	create_tunnel(tif, b->ha, b->coa);
	register_hoa(b->hoa, tif, b->homeif);
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

	// TODO deallocate tunnel here
	char tif[IFNAMSIZ];
	tunnel_name(tif, IFNAMSIZ, b->coa);
	deregister_hoa(b->hoa, tif, b->homeif);
	release_tunnel(tif);

	free(p);
	return 0;
}

int change_binding(struct binding *b, in_addr_t newcoa)
{
	char oldtif[IFNAMSIZ];
	tunnel_name(oldtif, IFNAMSIZ, b->coa);
	deregister_hoa(b->hoa, oldtif, b->homeif);
	release_tunnel(oldtif);

	char tif[IFNAMSIZ];
	tunnel_name(tif, IFNAMSIZ, newcoa);
	create_tunnel(tif, b->ha, newcoa);
	register_hoa(b->hoa, tif, b->homeif);

	b->coa = newcoa;

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
