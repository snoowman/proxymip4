#ifndef PMIP_NETWORK_HPP
#define PMIP_NETWORK_HPP

#include <netinet/in.h>

int create_tunnel(in_addr_t laddr, in_addr_t raddr);
int release_tunnel(in_addr_t raddr);

int register_hoa(in_addr_t hoa, in_addr_t coa, char const *hif);
int deregister_hoa(in_addr_t hoa, in_addr_t coa, char const *hif);

int set_proxy_arp(char const *mif, int flag);

int register_source_route(in_addr_t hoa, int tab, char const *mif);
int unregister_source_route(in_addr_t hoa, int tab, char const *mif);

int register_route_to_tunnel(in_addr_t ha, int tab);
int unregister_route_to_tunnel(in_addr_t ha, int tab);

int load_neigh(in_addr_t *addr, int max, char const *ifname);
void send_grat_arp(char const *device, in_addr_t *addr, int num_addr);

#endif
