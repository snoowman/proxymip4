#ifndef PMIP_COMMON_H
#define PMIP_COMMON_H

#include "rfc3344.h"

unsigned short in_cksum(void *addr, int len);
void randomize();
void sock_bind_if(int sock, char *ifname);
void sock_join_mcast(int sock, unsigned long mcast);
void sock_set_icmpfilter(int sock, int type);
unsigned long sock_get_if_addr(int sock, char* ifname);
int sock_get_if_prefix(int sock, char* ifname);
int popen2(char **cmd, int *rfd, int *wfd);
ssize_t authlen_by_spi(struct mip_reg_request *req);
int auth_by_spi(char *auth, struct mip_reg_request *req);
unsigned long long ntohll(unsigned long long ll);
#define htonll ntohll

#define ICMP_FILTER                     1
struct icmp_filter {
        unsigned long data;
};

#endif
