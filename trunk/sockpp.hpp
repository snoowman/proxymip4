#ifndef PMIP_SOCKPP_HPP
#define PMIP_SOCKPP_HPP

#include <strings.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <boost/noncopyable.hpp>
#include "posixpp.hpp"

namespace sockpp {

class in_address {
  sockaddr_in sa_; 

public:
  in_address() {
    bzero(&sa_, sizeof(sa_));
  }

  explicit in_address(char const *str, __u16 port = 0) {
    bzero(&sa_, sizeof(sa_));
    inet_aton_ex(str, &sa_.sin_addr);
    sa_.sin_port = htons(port);
  }

  explicit in_address(sockaddr_in const *sa) {
    memcpy(&sa_, sa, sizeof(sockaddr_in));
  }

  explicit in_address(sockaddr const *sa) {
    memcpy(&sa_, sa, sizeof(sockaddr_in));
  }

  explicit in_address(in_addr_t addr, __u16 port = 0) {
    bzero(&sa_, sizeof(sa_));
    sa_.sin_addr.s_addr = addr;
    sa_.sin_port = htons(port);
  }

  char *to_string() const {
    return inet_ntoa(sa_.sin_addr);
  }

  __u32 to_u32() const {
    return sa_.sin_addr.s_addr;
  }

  sockaddr const *sa() const {
    return (sockaddr *)&sa_;
  }

  socklen_t sa_len() const {
    return sizeof(sa_);
  }

  sockaddr *sa() {
    return (sockaddr *)&sa_;
  }

  socklen_t *sa_plen() {
    static socklen_t sa_len_;
    sa_len_ = sizeof(sa_);
    return &sa_len_;
  }

  __u16 port() {
    return ntohs(sa_.sin_port);
  }

  bool is_mcast() const {
    return IN_MULTICAST(ntohl(to_u32()));
  }

};

class in_iface;

class in_socket : private boost::noncopyable {
  int sock_;
  int type_;
  int protocol_;

public:
  in_socket(int type, int protocol = 0) {
    type_ = type;
    protocol_ = protocol;
    sock_ = 0;
    open();
  }

  ~in_socket() {
    close();
  }

  void open() {
    if (sock_)
      close();
    sock_ = socket_ex(PF_INET, type_, protocol_);

  }

  void close() {
    if (sock_) {
      close_ex(sock_);
      sock_ = 0;
    }
  }

  ssize_t send(void const *buf, size_t len) const {
    return send_ex(sock_, buf, len, 0);
  }

  ssize_t recv(void *buf, size_t size) const {
    return recv_ex(sock_, buf, size, 0);
  }

  ssize_t sendto(char const *buf, size_t len, in_address const& addr) const {
    return sendto_ex(sock_, buf, len, 0, addr.sa(), addr.sa_len());
  }

  ssize_t recvfrom(char *buf, size_t size, in_address& addr) const {
    return recvfrom_ex(sock_, buf, size, 0, addr.sa(), addr.sa_plen());
  }

  void reuse_addr(int reuse = 1) {
    setsockopt_ex(sock_, SOL_SOCKET, SO_REUSEADDR, (char *)&reuse, sizeof(int));
  }

  void bind(in_address const& addr) const {
    bind_ex(sock_, addr.sa(), addr.sa_len());
  }

  void rebind(in_address const& addr) {
    open();
    bind_ex(sock_, addr.sa(), addr.sa_len());
  }

  void join_mcast(in_address const& ma) const {
    if (!ma.is_mcast())
      throw std::invalid_argument("not multicast address");

    struct ip_mreq mreq;
    bzero(&mreq, sizeof(mreq));
    mreq.imr_multiaddr.s_addr = ma.to_u32();
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    setsockopt_ex2("join mcast",
    sock_, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
  }

  int select_read(timeval &tv) const {
    fd_set rfds;

    FD_ZERO(&rfds);
    FD_SET(sock_, &rfds);

    return select_ex(sock_ + 1, &rfds, NULL, NULL, &tv);
  }

  void bindif(in_iface const& in_iface) const;

  int sock() const {
    return sock_;
  }
};

class udp_socket : public in_socket {
public:
  udp_socket()
    : in_socket(SOCK_DGRAM)
  {}
};

int const ICMP_FILTER = 1;
struct icmp_filter {
        unsigned long data;
};

class icmp_socket : public in_socket {
public:
  icmp_socket()
    : in_socket(SOCK_RAW, IPPROTO_ICMP)
  {}

  void icmp_filter(int type) const {
    struct icmp_filter filt;
    filt.data = ~(1 << type);

    setsockopt_ex2("icmp_filter",
    sock(), SOL_RAW, ICMP_FILTER, (char*)&filt, sizeof(filt));
  }
};

class in_iface {
  udp_socket s_;
  ifreq ifr_;

public:
  in_iface(char const *ifname)
  {
    bzero(&ifr_, sizeof(ifr_));
    strncpy(ifr_.ifr_name, ifname, IFNAMSIZ-1);
    // validate ifname by getting index 
    index();
  }

  char const *name() const {
    return ifr_.ifr_name;
  }

  int index() const {
    ioctl_ex2("get_ifindex", s_.sock(), SIOCGIFINDEX, &ifr_);
    return ifr_.ifr_ifindex;
  }

  in_address addr() const {
    ioctl_ex2("get_ifaddr", s_.sock(), SIOCGIFADDR, &ifr_);
    return in_address(&ifr_.ifr_addr);
  }

  in_address netmask() const {
    ioctl_ex2("get_ifnetmask", s_.sock(), SIOCGIFNETMASK, &ifr_);
    return in_address(&ifr_.ifr_netmask);
  }

  int preflen() const {
    __u32 mask = ntohl(netmask().to_u32());
    int length = 0;

    for (int i = 31; i >= 0; --i) {
      if (!(mask & (1 << i)))
        break;
      ++length;
    }
    return length;
  }

  int flags() const {
    ioctl_ex2("get_ifflags", s_.sock(), SIOCGIFFLAGS, &ifr_);
    return ifr_.ifr_flags;
  }
};

inline void in_socket::bindif(in_iface const &ifa) const {
  setsockopt_ex2("bindif", 
    sock_, SOL_SOCKET, SO_BINDTODEVICE, ifa.name(), strlen(ifa.name()) + 1);
}

} // name sockpp

#endif
