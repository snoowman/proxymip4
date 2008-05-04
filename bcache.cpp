#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include "network.hpp"
#include "bcache.hpp"

namespace bcache {

void generic_bcache::register_binding(in_addr_t hoa, in_addr_t ha, in_addr_t coa, __u32 spi, __u16 lifetime)
{
  deregister_binding(hoa);

  // store binding values
  binding & b = bindings_[hoa];
  b.hoa = hoa;
  b.ha = ha;
  b.coa = coa;
  b.spi = spi;

  if (lifetime == 0xffff)
    b.timeout = 0;
  else
    b.timeout = time(NULL) + ntohs(lifetime);

  // call virtual function
  register_binding_callback(hoa, ha, coa);
}

bool generic_bcache::deregister_binding(in_addr_t hoa)
{
  if (bindings_.find(hoa) == bindings_.end())
    return false;

  binding const &b = bindings_[hoa];
  // call virtual function
  deregister_binding_callback(hoa, b.ha, b.coa);
  // remove binding
  bindings_.erase(hoa);
  return true;
}

void generic_bcache::list_binding()
{
  printf("binding generic_bcache\n");

  std::map<in_addr_t, binding>::iterator i;
  for(i = bindings_.begin(); i != bindings_.end(); ++i) {
    binding const& b = i->second;
    printf("  hoa:%08x ha:%08x coa:%08x life: ", b.hoa, b.ha, b.coa);

    if (b.timeout == 0)
      printf("infinite\n");
    else
      printf("%lu (s)\n", b.timeout - time(NULL));
  }
  printf("\n");
}

void ha_bcache::register_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
  if (coa_refcnt_[coa]++ == 0)
    create_tunnel(ha, coa);
  register_hoa(hoa, coa, hif_.name());
}

void ha_bcache::deregister_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
  deregister_hoa(hoa, coa, hif_.name());
  if (--coa_refcnt_[coa] == 0)
    release_tunnel(coa);
}

void pma_bcache::register_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
  printf("reg\n");
  char const *ifname = miface_[hoa].c_str();

  if (ha_refcnt_[ha]++ == 0)
    create_tunnel(coa, ha);

  int &tab = tunnel_tab_[ha];
  if (mif_refcnt_[ifname]++ == 0) {
    tab = allocate_rtable();
    register_route_to_tunnel(ha, tab);
  }

  set_proxy_arp(ifname, 1);
  register_source_route(hoa, tab, ifname);
}

void pma_bcache::deregister_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
  printf("dereg\n");
  char const *ifname = miface_[hoa].c_str();

  int &tab = tunnel_tab_[ha];
  unregister_source_route(hoa, tab, ifname);
  set_proxy_arp(ifname, 0);

  if (--mif_refcnt_[ifname] == 0) {
    unregister_route_to_tunnel(ha, tab);
    free_rtable(tab);
  }

  if (ha_refcnt_[ha]++ == 0)
    release_tunnel(ha);
}

} // namespace bgeneric_bcache
