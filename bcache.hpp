#ifndef MIP_BCACHE_H
#define MIP_BCACHE_H

#include <asm/types.h>
#include <netinet/in.h>
#include <map>
#include <string>
#include <stdexcept>
#include "sockpp.hpp"

namespace bcache {

struct binding {
	in_addr_t hoa;
	in_addr_t ha;
	in_addr_t coa;
	__u32     spi;
	time_t    timeout;
};

class generic_bcache {
  std::map<in_addr_t, binding> bindings_;

public:
  virtual ~generic_bcache() {};
  void list_binding();
  void register_binding(in_addr_t hoa, in_addr_t ha, in_addr_t coa, __u32 spi, __u16 lifetime);
  bool deregister_binding(in_addr_t hoa);
  void deregister_local(in_addr_t hoa, in_addr_t ha, in_addr_t coa);

protected:
  virtual void register_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa) = 0;
  virtual void deregister_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa) = 0;
};

class ha_bcache : public generic_bcache {
  sockpp::in_iface const &hif_;  
  std::map<in_addr_t, int> coa_refcnt_;

public:
  ha_bcache(sockpp::in_iface const& hif)
    : hif_(hif)
  { }

protected:
  virtual void register_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa);
  virtual void deregister_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa);
};

class no_rtable : public std::runtime_error
{
public:
  no_rtable() throw() 
    : runtime_error("no policy route table available")
  { }
  virtual ~no_rtable() throw()
  {}
};

class pma_bcache : public generic_bcache {
public:
  static const int MAX_CLIENT = 250; // hard limit of max policy route table id
  std::map<in_addr_t, int> ha_refcnt_;
  std::map<std::string, int> mif_refcnt_;
  std::map<in_addr_t, std::string> miface_;
  std::map<in_addr_t, int> tunnel_tab_;
  int rtable_pool_[MAX_CLIENT];

private:
  int allocate_rtable() {
    for (int i = 0; i < MAX_CLIENT; ++i) {
      if (rtable_pool_[i] == 0) {
        rtable_pool_[i] = 1;
        return i;
      }
    }
    throw no_rtable();
  }

  void free_rtable(int tab) {
    rtable_pool_[tab] = 0;
  }

public:
  void register_mif(in_addr_t hoa, char const* ifname) {
    miface_[hoa] = ifname;
  }

protected:
  virtual void register_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa);
  virtual void deregister_binding_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa);
};

} // namespace bcache

#endif
