#ifndef MIP_BCACHE_H
#define MIP_BCACHE_H

#include <asm/types.h>
#include <netinet/in.h>
#include <strings.h>
#include <map>
#include <string>
#include <stdexcept>
#include "sockpp.hpp"
#include "rfc3344.hpp"
#include "network.hpp"

namespace bcache {

struct binding {
	in_addr_t hoa;
	in_addr_t ha;
	in_addr_t coa;
	time_t    timeout;
};

class generic_bcache {
  std::map<in_addr_t, binding> bindings_;
  static generic_bcache *singleton;

protected:
  in_addr_t homecn_[rfc3344::HOMECN_MAX];
  int num_homecn_;

private:
  binding* add_binding(in_addr_t hoa, in_addr_t ha, in_addr_t coa);
  void remove_binding(in_addr_t hoa, in_addr_t ha, in_addr_t coa);

public:
  generic_bcache() {
    num_homecn_ = 0;
    if (singleton == 0)
      singleton = this;
  }

  virtual ~generic_bcache() {
    singleton = 0;
  };

  void store_homecn(in_addr_t *homecn, int num) {
    memcpy(homecn_, homecn, num * sizeof(in_addr_t));
    num_homecn_ = num;
  }

  static void list_binding(char const *pname);
  void update_binding(in_addr_t hoa, in_addr_t ha, in_addr_t coa, __u16 lifetime);

protected:
  virtual void register_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa) = 0;
  virtual void deregister_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa) = 0;
  virtual void update_callback(in_addr_t hoa) {};
  virtual void return_home_callback(in_addr_t hoa) {};
  virtual void leave_home_callback(in_addr_t hoa) {};
};

class ha_bcache : public generic_bcache {
  sockpp::in_iface const &hif_;  
  std::map<in_addr_t, int> coa_refcnt_;
  std::map<in_addr_t, mac_addr> hoa_mac_;

public:
  ha_bcache(sockpp::in_iface const& hif)
    : hif_(hif)
  { }

  void store_mac(in_addr_t hoa, mac_addr *mac) {
    hoa_mac_[hoa] = *mac;
  }

protected:
  virtual void register_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa);
  virtual void deregister_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa);
  virtual void return_home_callback(in_addr_t hoa);
  virtual void leave_home_callback(in_addr_t hoa);
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
        return i + 1;
      }
    }
    throw no_rtable();
  }

  void free_rtable(int tab) {
    rtable_pool_[tab - 1] = 0;
  }

public:
  pma_bcache() {
    bzero(rtable_pool_, sizeof(rtable_pool_));
  }

  void store_mif(in_addr_t hoa, char const* ifname) {
    miface_[hoa] = ifname;
  }

protected:
  virtual void register_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa);
  virtual void deregister_callback(in_addr_t hoa, in_addr_t ha, in_addr_t coa);
  virtual void update_callback(in_addr_t hoa);
};

} // namespace bcache

#endif
