#ifndef MIP_BCACHE_H
#define MIP_BCACHE_H

#include <asm/types.h>
#include <netinet/in.h>

struct binding {
	in_addr_t hoa;
	in_addr_t ha;
	in_addr_t coa;
	__u64 lastid;
	char *homeif;
	time_t timeout;
	struct binding *next;
};

int add_binding(struct binding *b);
int remove_binding(struct binding *b);
int change_binding(struct binding *b, in_addr_t newcoa);
struct binding *find_binding(in_addr_t hoa);
void list_binding();

#endif
