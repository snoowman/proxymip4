#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <string>
#include "network.hpp"
#include "bcache.hpp"

namespace bcache {

void cache::register_binding(in_addr_t hoa, in_addr_t ha, in_addr_t coa, __u16 lifetime)
{
  if (bindings_.find(hoa) != bindings_.end())
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

  // setup network for hoa
  if (coa_refcnt_[coa] == 0) {
    create_tunnel(ha, coa);
    ++coa_refcnt_[coa];
  }
  register_hoa(hoa, coa, hif_.name());
}

bool cache::deregister_binding(in_addr_t hoa)
{
  if (bindings_.find(hoa) == bindings_.end())
    return false;

  binding const &b = bindings_[hoa];
  // free network resource
  deregister_hoa(b.hoa, b.coa, hif_.name());
  if (coa_refcnt_[b.coa] > 0) {
    --coa_refcnt_[b.coa];
    release_tunnel(b.coa);
  }

  // remove binding
  bindings_.erase(hoa);
  return true;
}

void cache::list_binding()
{
  printf("binding cache\n");

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

} // namespace bcache
