#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include "network.hpp"
#include "bcache.hpp"
#include "config.hpp"
#include "sockpp.hpp"

namespace bcache {

generic_bcache *generic_bcache::singleton;

void generic_bcache::register_binding(in_addr_t hoa, in_addr_t ha, in_addr_t coa, __u16 lifetime)
{
  deregister_binding(hoa);

  // store binding values
  binding & b = bindings_[hoa];
  b.hoa = hoa;
  b.ha = ha;
  b.coa = coa;

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

void generic_bcache::list_binding(char const *pname)
{
  generic_bcache *me = generic_bcache::singleton;
  if (me == 0)
    return;

  char fn[1024];
  snprintf(fn, 1024, BCACHE_FILE_FMT, pname);
  FILE *fp = fopen(fn, "w");
  if (fp == NULL)
    return;

  fprintf(fp, "Home Addr       Home Agent      Care-of Addr    Lifetime    \n");

  std::map<in_addr_t, binding>::iterator i;
  for(i = me->bindings_.begin(); i != me->bindings_.end(); ++i) {
    binding const& b = i->second;
    fprintf(fp, "%-16s", sockpp::in_address(b.hoa).to_string());
    fprintf(fp, "%-16s", sockpp::in_address(b.ha).to_string());
    fprintf(fp, "%-16s", sockpp::in_address(b.coa).to_string());

    if (b.timeout == 0)
      fprintf(fp, "infinite\n");
    else
      fprintf(fp, "%lu (s)\n", b.timeout - time(NULL));
  }
  fclose(fp);
}

void ha_bcache::register_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
  if (coa_refcnt_[coa]++ == 0)
    create_tunnel(ha, coa);

  register_hoa(hoa, coa, hif_.name());
  send_grat_arp(hif_.name(), &hoa, 1);
}

void ha_bcache::deregister_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
  deregister_hoa(hoa, coa, hif_.name());
  if (--coa_refcnt_[coa] == 0)
    release_tunnel(coa);

  /* return HOME: ARP are sent for MN to update HOME CN's ARP */
  send_grat_arp(hif_.name(), homecn_, num_homecn_);
}

void pma_bcache::register_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
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

  /* register to PMA: ARP are sent for MN to update HOME CN's ARP */
  send_grat_arp(ifname, homecn_, num_homecn_);
}

void pma_bcache::deregister_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
  char const *ifname = miface_[hoa].c_str();

  int &tab = tunnel_tab_[ha];
  unregister_source_route(hoa, tab, ifname);
  set_proxy_arp(ifname, 0);

  if (--mif_refcnt_[ifname] == 0) {
    unregister_route_to_tunnel(ha, tab);
    free_rtable(tab);
  }

  if (--ha_refcnt_[ha] == 0)
    release_tunnel(ha);
}

} // namespace bcache
