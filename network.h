#ifndef MIP_NETWORK_H
#define MIP_NETWORK_H

#include <netinet/in.h>

int tunnel_name(char *buf, size_t size, in_addr_t raddr);
int create_tunnel(char *tif, in_addr_t laddr, in_addr_t raddr);
int release_tunnel(char *tif);

int register_hoa(in_addr_t hoa, char *tif, char *hif);
int deregister_hoa(in_addr_t hoa, char *tif, char *hif);

int table_index(char *tif);

int set_proxy_arp(char *mif, int flag);

int register_source_route(in_addr_t hoa, int tab, char *mif);
int unregister_source_route(in_addr_t hoa, int tab, char *mif);

#endif
