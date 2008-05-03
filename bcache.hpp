#ifndef MIP_BCACHE_H
#define MIP_BCACHE_H

#include <asm/types.h>
#include <netinet/in.h>
#include <map>
#include "sockpp.hpp"

namespace bcache {

struct binding {
	in_addr_t hoa;
	in_addr_t ha;
	in_addr_t coa;
	time_t timeout;
};

class cache {
  sockpp::in_iface const &hif_;  
  std::map<in_addr_t, binding> bindings_;
  std::map<in_addr_t, int> coa_refcnt_;

public:
  cache(sockpp::in_iface const& hif)
    : hif_(hif)
  { }

  void list_binding();
  void register_binding(in_addr_t hoa, in_addr_t ha, in_addr_t coa, __u16 lifetime);
  bool deregister_binding(in_addr_t hoa);
};

} // namespace bcache

#endif
