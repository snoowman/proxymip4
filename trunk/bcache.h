#ifndef MIP_BCACHE_H
#define MIP_BCACHE_H

#include <asm/types.h>
#include <netinet/in.h>

struct binding {
	in_addr_t hoa;
	in_addr_t ha;
	in_addr_t coa;
	__u64 lastid;
	time_t timeout;
	struct binding *next;
};

int add_binding(struct binding *b);
int remove_binding(struct binding *b);
struct binding *find_binding(in_addr_t hoa);
void list_binding();

#endif
