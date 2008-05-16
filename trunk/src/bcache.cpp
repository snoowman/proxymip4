#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <syslog.h>
#include <string>
#include "network.hpp"
#include "bcache.hpp"
#include "config.hpp"
#include "sockpp.hpp"
#include "rfc3344.hpp"

namespace bcache {

generic_bcache *generic_bcache::singleton;

void generic_bcache::remove_binding(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
  if (bindings_.find(hoa) == bindings_.end()) {
    deregister_callback(hoa, ha, coa);
    return;
  }
  deregister_callback(hoa, bindings_[hoa].ha, bindings_[hoa].coa);
  return_home_callback(hoa);
  bindings_.erase(hoa);
}

binding *generic_bcache::add_binding(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
  binding *ret;
  if (bindings_.find(hoa) == bindings_.end()) {
    register_callback(hoa, ha, coa);
    leave_home_callback(hoa);
    ret = &bindings_[hoa];
  }
  else {
    ret = &bindings_[hoa];
    if(ret->coa != coa || ret->ha != ret->ha) {
      deregister_callback(hoa, ret->ha, ret->coa);
      register_callback(hoa, ha, coa);
    }
    else {
      update_callback(hoa);
    }
  }
  return ret;
}

void generic_bcache::update_binding(in_addr_t hoa, in_addr_t ha, in_addr_t coa, __u16 lifetime)
{
  if (lifetime == 0) {
    remove_binding(hoa, ha, coa);
    return;
  }

  binding *b = add_binding(hoa, ha, coa);
  b->hoa = hoa;
  b->ha = ha;
  b->coa = coa;
  if (lifetime == 0xffff)
    b->timeout = 0;
  else
    b->timeout = time(NULL) + ntohs(lifetime);
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

void ha_bcache::register_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
  if (coa_refcnt_[coa]++ == 0)
    create_tunnel(ha, coa);
  register_hoa_route(hoa, coa, hif_.name());
}

void ha_bcache::deregister_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
  deregister_hoa_route(hoa, coa, hif_.name());
  if (coa_refcnt_[coa] == 0 || --coa_refcnt_[coa] == 0)
    release_tunnel(coa);
}

void ha_bcache::leave_home_callback(in_addr_t hoa)
{
  /* leave HOME: ARP are sent to HOME CN to update MN's MAC */
  register_hoa(hoa, hif_.name());
  send_grat_arp(hif_.name(), &hoa, 1);
}

void ha_bcache::return_home_callback(in_addr_t hoa)
{
  /* return HOME: ARP are sent to MN to update HOME CN's MAC */
  num_homecn_ += load_neigh(homecn_ + num_homecn_, rfc3344::HOMECN_MAX - num_homecn_, hif_.name(), hoa);
  syslog(LOG_DEBUG, "send %d ARP", num_homecn_);
  send_grat_arp(hif_.name(), homecn_, num_homecn_, false);
  deregister_hoa(hoa, hif_.name());
  /* return HOME: ARP are sent to HOME CN to update MN's MAC */
  if (hoa_mac_.find(hoa) != hoa_mac_.end())
    send_grat_arp2(hif_.name(), hoa, &hoa_mac_[hoa]);
}

void pma_bcache::register_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
  char const *ifname = miface_[hoa].c_str();

  if (ha_refcnt_[ha]++ == 0)
    create_tunnel(coa, ha);

  int &tab = tunnel_tab_[ha];
  if (mif_refcnt_[ifname]++ == 0) {
    tab = allocate_rtable();
    register_route_to_tunnel(ha, tab);
    set_proxy_arp(ifname, 1);
  }

  register_source_route(hoa, tab, ifname);

  /* register to PMA: ARP are sent for MN to update HOME CN's MAC */
  syslog(LOG_DEBUG, "send %d ARP", num_homecn_);
  send_grat_arp(ifname, homecn_, num_homecn_);
}

void pma_bcache::update_callback(in_addr_t hoa)
{
  char const *ifname = miface_[hoa].c_str();
  syslog(LOG_DEBUG, "update %d ARP", num_homecn_);
  send_grat_arp(ifname, homecn_, num_homecn_);
}

void pma_bcache::deregister_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
  char const *ifname = miface_[hoa].c_str();

  int &tab = tunnel_tab_[ha];
  unregister_source_route(hoa, tab, ifname);

  if (mif_refcnt_[ifname] == 0 || --mif_refcnt_[ifname] == 0) {
    set_proxy_arp(ifname, 0);
    unregister_route_to_tunnel(ha, tab);
    free_rtable(tab);
  }

  if (ha_refcnt_[ha] == 0 || --ha_refcnt_[ha] == 0)
    release_tunnel(ha);

  /* unregister from PMA: ARP are sent to HOME CN to update MN's MAC */
  send_grat_arp(ifname, &hoa, 1);
}

} // namespace bcache
