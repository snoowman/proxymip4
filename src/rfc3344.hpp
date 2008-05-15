/*
 * http://tools.ietf.org/html/rfc1256
 */

#ifndef PMIP_RFC3344_HPP
#define PMIP_RFC3344_HPP

#include <stdio.h>
#include <syslog.h>
#include <asm/types.h>
#include <netinet/in.h>
#include <map>
#include "rfc1256.hpp"
#include "sockpp.hpp"
#include "packet.hpp"
#include "sadb.hpp"

namespace rfc3344 {

int const RA_EXTTYPE_MOBIAGENT = 16;
int const RA_EXTTYPE_PREFLEN = 19;

int const MIP_PORT = 434;
int const MIPTYPE_REQUEST = 1;
int const MIPTYPE_REPLY = 3;
int const MIP_EXTTYPE_AUTH = 32;

int const MIP_AUTH_MAX = 255;

int const MIPCODE_ACCEPT = 0;
int const MIPCODE_BAD_ACCESS = 129;
int const MIPCODE_BAD_AUTH = 131;
int const MIPCODE_BAD_ID = 133;
int const MIPCODE_BAD_FORMAT = 134;
int const MIPCODE_BAD_HA = 136;

template <typename T>
size_t mip_msg_authsize(T msg)
{
  if (sizeof(msg.auth))
    ;
  return sizeof(T) - MIP_AUTH_MAX;
}

template <typename T>
size_t mip_msg_size(T msg)
{
  return sizeof(T) - MIP_AUTH_MAX + msg.auth.length - 4;
}

struct ra_ext_hdr {
  __u8 type;
  __u8 length;
};

struct ra_ext_magent_adv {
  __u16 sequence;
  __u16 lifetime;
  union {
    struct {
      __u8 flag_T:1;
      __u8 flag_r:1;
      __u8 flag_G:1;
      __u8 flag_M:1;
      __u8 flag_F:1;
      __u8 flag_H:1;
      __u8 flag_B:1;
      __u8 flag_R:1;
    };
    __u8 flags;
  };
  __u8 reserved;
} __attribute__((packed));

struct mip_ext_auth {
  __u8 type;
  __u8 length;
  __u32 spi;
  char auth[MIP_AUTH_MAX];
} __attribute__((packed));

struct mip_rrq {
  __u8 type;
  union {
    struct {
      __u8 flag_x:1;
      __u8 flag_T:1;
      __u8 flag_r:1;
      __u8 flag_G:1;
      __u8 flag_M:1;
      __u8 flag_D:1;
      __u8 flag_B:1;
      __u8 flag_S:1;
    };
    __u8 flags;
  };
  __u16 lifetime;
  in_addr_t hoa;
  in_addr_t ha;
  in_addr_t coa;
  __u64 id;
  struct mip_ext_auth auth;
} __attribute__((packed));

struct mip_rrp {
  __u8 type;
  __u8 code;
  __u16 lifetime;
  in_addr_t hoa;
  in_addr_t ha;
  __u64 id;
  struct mip_ext_auth auth;
} __attribute__((packed));

__u64 time_stamp();

class rtadv_socket {
  sockpp::icmp_socket icmp_;
  sockpp::in_iface const &ifa_;
  rfc1256::router_vars &vars_;

private:
  int create_rtadv_msg(char *buf, ssize_t size)
  {
    ssize_t rtadv_len = 8 + 8 + 8 + 3 + 1;
    if (size < rtadv_len)
      throw packet::invalid_length();

    // len = ICMP header + 1 address + mipext + prefixext + padding;
    bzero(buf, rtadv_len);
  
    struct icmp *icmp = (struct icmp *)buf;
    icmp->icmp_type = rfc1256::ICMP_ROUTER_ADV;
    icmp->icmp_code = 16;
    icmp->icmp_num_addrs = 1;
    icmp->icmp_wpa = 2;
    icmp->icmp_lifetime = htons(vars_.adv_lifetime());
  
    struct icmp_ra_addr *ra_addr = (struct icmp_ra_addr *)(buf + 8);
    ra_addr->ira_addr = ifa_.addr().to_u32();
    ra_addr->ira_preference = 0;
  
    ra_ext_hdr *ext = (ra_ext_hdr *)(buf + 16);
    ext->type = RA_EXTTYPE_MOBIAGENT;
    ext->length = sizeof(ra_ext_magent_adv);
  
    ra_ext_magent_adv *madv = (ra_ext_magent_adv *)(buf + 18);
    madv->sequence = htons(vars_.increase_seq());
    madv->lifetime = 0xffff;
    madv->flag_H = 1;
  
    ra_ext_hdr *ext2 = (ra_ext_hdr *)(buf + 24);
    ext2->type = RA_EXTTYPE_PREFLEN;
    ext2->length = 1;
  
    __u16 *ppreflen = (__u16 *)(buf + 26);
    *ppreflen = ifa_.preflen();
  
    icmp->icmp_cksum = packet::in_cksum(icmp, rtadv_len);
  
    return rtadv_len;
  }

public:
  rtadv_socket(sockpp::in_iface const &ifa, rfc1256::router_vars &vars)
    : ifa_(ifa), vars_(vars)
  {
    icmp_.bindif(ifa); 
    icmp_.join_mcast(sockpp::in_address(htonl(INADDR_ALLRTRS_GROUP)));
    icmp_.icmp_filter(rfc1256::ICMP_ROUTER_SOL);
  }
  
  void send_rtadv(sockpp::in_address dest) {
    char buf[packet::MTU];  
    int len = create_rtadv_msg(buf, packet::MTU);
    icmp_.sendto(buf, len, dest);
  }

  sockpp::in_address recv_rtsol() {
    char buf[packet::MTU];

    sockpp::in_address ret;
    int len = icmp_.recvfrom(buf, packet::MTU, ret);
    
    struct icmp *p = (struct icmp*) (buf + sizeof(struct ip));
    len -= sizeof(struct ip);
    if (packet::in_cksum(p, len) != 0)
      throw packet::bad_packet("bad icmp cksum");
  
    if (p->icmp_type != rfc1256::ICMP_ROUTER_SOL)
      throw packet::bad_packet("unexpected icmp type");

    return ret;
  }

  void serv_multicast() {
    sockpp::in_address multicast(htonl(INADDR_ALLHOSTS_GROUP));

    try {
      for (;;) {
        send_rtadv(multicast);
  
        timeval tv = vars_.adv_interval();
        syslog(LOG_INFO, "sending rtadv after %lu.%06lu s delay\n", tv.tv_sec, tv.tv_usec);
        reply_unicast_timeout(tv);
      }
    }
    catch (std::exception &e) {
      syslog(LOG_ERR, "error: %s", e.what());
    }
  }

  void reply_unicast_timeout(timeval &tv) {
    while(icmp_.select_read(tv) > 0) {
      try {
        sockpp::in_address sol_addr = recv_rtsol();
        send_rtadv(sol_addr);
      }
      catch (packet::bad_packet &e) {
        syslog(LOG_WARNING, "%s\n", e.what());
      }
    }
  }
};

class rtsol_socket {
  sockpp::icmp_socket icmp_;

private:
  int create_rtsol_msg(void* buf, ssize_t size) {
    ssize_t rtsol_len = 8 /* ICMP header */;
    if (size < rtsol_len)
      throw packet::invalid_length();
  
    bzero(buf, rtsol_len);
  
    struct icmphdr *icmp = (struct icmphdr *)buf;
    icmp->type = rfc1256::ICMP_ROUTER_SOL;
    icmp->checksum = packet::in_cksum(icmp, rtsol_len);
  
    return rtsol_len;
  }

public:
  rtsol_socket() {
    icmp_.join_mcast(sockpp::in_address(htonl(INADDR_ALLHOSTS_GROUP)));
    icmp_.icmp_filter(rfc1256::ICMP_ROUTER_ADV);
  }

  void bindif(sockpp::in_iface const &ifa) {
    icmp_.bindif(ifa);
  }

  void send_rtsol() {
    char buf[packet::MTU];
    int len = create_rtsol_msg(buf, packet::MTU);

    sockpp::in_address dest(htonl(INADDR_ALLRTRS_GROUP));
    icmp_.sendto(buf, len, dest);
  }

  void delay() {
      int sec = rand() % rfc1256::MaxSolDelay;
      int usec = rand() % 1000000;
      printf("sending rtsol with %d.%06d s delay\n", sec, usec);
      sleep(sec);
      usleep(usec);
  }

  void solicit() {
    randomize();

    int i;
    for (i = 0; i < rfc1256::MaxSolNum; ++i) {
      delay();
      send_rtsol();
  
      if (recv_rtadv())
        break;
    }
  
    if (i == rfc1256::MaxSolNum) {
      printf("no router advertisement received. exit!\n");
      exit(-1);
    }
  }

  bool recv_rtadv()
  {
    struct timeval tv;
    tv.tv_sec = rfc1256::SolInterval;
    tv.tv_usec = 0;

    char buf[packet::MTU];
    if(icmp_.select_read(tv)) {
      int len = icmp_.recv(buf, packet::MTU);
      print_rtadv(buf, len);
      return true;
    }

    printf("no rtadv received in %d seconds\n", rfc1256::SolInterval); 
    return false;
  }

  void print_rtadv(char *buf, int len)
  {
    struct icmp *p = (struct icmp*) (buf + sizeof(struct ip));
    len -= sizeof(struct ip);
  
    if (p->icmp_type == rfc1256::ICMP_ROUTER_ADV) {
      printf("received router advertisement\n");
      printf("    icmp len %d, cksum %hu, recksum %hu\n", 
        len, p->icmp_cksum, packet::in_cksum(p, len));
      printf("    icmp type %hhu, code %hhu, naddr %hhu, wpa %hhu, life %hu\n", 
        p->icmp_type, p->icmp_code, 
        p->icmp_num_addrs, p->icmp_wpa, 
        ntohs(p->icmp_lifetime));
  
      int i;
      struct icmp_ra_addr *pa = &p->icmp_radv;
      if (len > 8 + p->icmp_num_addrs * p->icmp_wpa * 4) {
        ra_ext_hdr *ext = (ra_ext_hdr *)(buf + 28 + p->icmp_num_addrs * p->icmp_wpa * 4);
        if (ext->type == RA_EXTTYPE_MOBIAGENT) {
          printf("mobile agent advertisement extension\n");
          ra_ext_magent_adv *madv = (ra_ext_magent_adv *)((char *)ext + sizeof(*ext));
          printf("    seq %hu, lifetime %hu, flags %hhu\n", 
            ntohs(madv->sequence), ntohs(madv->lifetime), madv->flags);
        }
        ra_ext_hdr *ext2 = (ra_ext_hdr *)((char *)ext + sizeof(*ext) + ext->length);
        if (ext2->type == RA_EXTTYPE_PREFLEN) {
          __u8 *prefix = (__u8 *)((char *)ext2 + 2);
          for (i = 0; i < p->icmp_num_addrs; ++i) {
            in_addr tmp;
            tmp.s_addr = pa[i].ira_addr;
  
            printf("    home agent %d, address %s, preference %hu, prefix %hhu\n", i,
              inet_ntoa(tmp), ntohs(pa[i].ira_preference), prefix[i]);
          }
        }
      }
      else {
        for (i = 0; i < p->icmp_num_addrs; ++i) {
          struct in_addr tmp;
          tmp.s_addr = pa[i].ira_addr;
  
          printf("    router %d, address %s, preference %hu\n", i,
            inet_ntoa(tmp), ntohs(pa[i].ira_preference));
        }
      }
    }
  }
};

inline __u64 time_stamp()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  __u64 ret;

  // NTP epoch time is 1900, Linux epoch time is 1970
  // we need to add those seconds
  tv.tv_sec += 25567u * 24u * 3600u;

  ret = rand() & ((1 << 12) - 1);

  // for lower 32 bit
  //     top 20 bits (12 ~ 31) represent microsecond
  //   difference between 2^20 and 1 million ignored
  //     bottom 0 - 11 bits generated by rand
  ret |= (__u64)tv.tv_usec << 12;
  ret |= (__u64)tv.tv_sec << 32;

  return ret;
}

class ha_socket {
  sockpp::udp_socket mip_;
  sockpp::in_iface const &homeif_;
  std::map<__u32, __u64> lastid_;

private:
  struct mip_rrp create_rrp(struct mip_rrq const &q, int errcode)
  {
    struct mip_rrp p;
    bzero((char *) &p, sizeof(p));

    p.type = MIPTYPE_REPLY;
    p.code = errcode;
    p.lifetime = q.lifetime;
    p.hoa = q.hoa;
    p.ha = q.ha;
    p.id = q.id;
  
    sadb::mipsa *sa = sadb::find_sa(ntohl(q.auth.spi));
  
    p.auth.type = MIP_EXTTYPE_AUTH;
    p.auth.spi = q.auth.spi;
    if (sa) {
      p.auth.length = authlen_by_sa(sa);
      auth_by_sa(p.auth.auth, &p, mip_msg_authsize(p), sa);
    }
    else {
      p.auth.length = q.auth.length;
    }
    return p;
  }

  int verify_rrq(struct mip_rrq &q, size_t len)
  {
    if (q.type != MIPTYPE_REQUEST) {
      syslog(LOG_WARNING, "incorrect MIP type value %d\n", q.type);
      return MIPCODE_BAD_FORMAT;
    }
  
    if (len > sizeof(q) || len < mip_msg_authsize(q)) {
      syslog(LOG_WARNING, "incorrect packet length %d\n", len);
      return MIPCODE_BAD_FORMAT;
    }

    if (len != mip_msg_size(q)) {
      syslog(LOG_WARNING, "incorrect packet length %d\n", len);
      return MIPCODE_BAD_FORMAT;
    }
  
    if (q.ha != homeif_.addr().to_u32()) {
      syslog(LOG_WARNING, "incorrect home agent address %08x\n", q.ha);
      return MIPCODE_BAD_HA;
    }
  
    sadb::mipsa *sa = sadb::find_sa(ntohl(q.auth.spi));
    if (!sa) {
      syslog(LOG_WARNING, "incorrect spi %u\n", ntohl(q.auth.spi));
      return MIPCODE_BAD_AUTH;
    }
  
    int authlen = authlen_by_sa(sa);
    if (authlen != q.auth.length) {
      syslog(LOG_WARNING, "incorrect auth length %d", authlen);
      return MIPCODE_BAD_FORMAT;
    }
  
    if (!verify_by_sa(q.auth.auth, &q, mip_msg_authsize(q), sa)) {
      syslog(LOG_WARNING, "mobile node failed authentication\n");
      return MIPCODE_BAD_AUTH;
    }

    __u64 id = ntohll(q.id);
    __u64 t1 = id >> 32;
    __u64 t2 = time_stamp() >> 32;
    
    if ((unsigned int)abs(t1 - t2) > sa->delay) {
      syslog(LOG_WARNING, "time not synchronized\n");

      // reset q id to home agent's time
      id &= (1LLU << 32) - 1;
      id |= t2 << 32;
      q.id = htonll(id);
      return MIPCODE_BAD_ID;
    }

    if (lastid_[q.hoa] == 0) {
      lastid_[q.hoa] = id;
    }
    else if (id <= lastid_[q.hoa]) {
      syslog(LOG_WARNING, "identifier smaller than previous one\n");
      return MIPCODE_BAD_ID;
    }
  
    return MIPCODE_ACCEPT;
  }

public:
  ha_socket(sockpp::in_iface const &homeif)
    : homeif_(homeif)
  {
    sockpp::in_address src_addr(INADDR_ANY, MIP_PORT);
    mip_.bind(src_addr);
    sadb::load_sadb();
  }

  int select_read(struct timeval &tv) {
    return mip_.select_read(tv);
  }

  int recv(mip_rrq &q, sockpp::in_address &from) {
      size_t len = mip_.recvfrom((char *)&q, packet::MTU, from);
      return verify_rrq(q, len);
  }

  void reply(int errcode, mip_rrq &q, sockpp::in_address &from) {
      struct mip_rrp p = create_rrp(q, errcode);
      mip_.sendto((char *)&p, mip_msg_size(p), from);
  }
};

class pma_socket {
  sockpp::udp_socket mip_;

private:
  void create_rrq(struct mip_rrq *q, in_addr_t hoa, in_addr_t ha, in_addr_t coa, sadb::mipsa *sa, __u16 lifetime)
  {
    bzero(q, sizeof(*q));
    q->type = MIPTYPE_REQUEST;
    q->flag_T = 1;
    q->lifetime = htons(lifetime);
  
    q->hoa = hoa;
    q->ha = ha;
    q->coa = coa;
    q->id = htonll(time_stamp());
  
    q->auth.type = MIP_EXTTYPE_AUTH;
    q->auth.spi = htonl(sa->spi);
  
    q->auth.length = authlen_by_sa(sa);
    auth_by_sa(q->auth.auth, q, mip_msg_authsize(*q), sa);
  }

  void verify_rrp(struct mip_rrp const &p, size_t len, struct mip_rrq const &q)
  {
    if (p.type != MIPTYPE_REPLY)
      throw packet::bad_packet("incorrect MIP type");
    if (len != mip_msg_size(p))
      throw packet::bad_packet("incorrect packet length");
    if (p.hoa != q.hoa)
      throw packet::bad_packet("incorrect home address");
    if (p.ha != q.ha)
      throw packet::bad_packet("incorrect care-of address");
  
    sadb::mipsa *sa = sadb::find_sa(ntohl(p.auth.spi));
    if (!sa)
      throw sadb::invalid_spi();

    int authlen = authlen_by_sa(sa);
    if (authlen != p.auth.length)
      throw packet::bad_packet("incorrect auth length");

    if (!verify_by_sa(p.auth.auth, &p, mip_msg_authsize(p), sa))
      throw packet::bad_packet("authentication failed ");
  }

public:
  pma_socket() {
    sadb::load_sadb();
    randomize();
    mip_.reuse_addr();
  }

  struct mip_rrp request(in_addr_t hoa, in_addr_t ha, in_addr_t coa, __u32 spi, __u16 lifetime) {
    sadb::mipsa *sa = sadb::find_sa(spi);

    if (!sa)
      throw sadb::invalid_spi();

    sockpp::in_address coa_port(coa);
    mip_.rebind(coa_port);

    struct mip_rrq q;
    create_rrq(&q, hoa, ha, coa, sa, lifetime);

    sockpp::in_address ha_port(ha, MIP_PORT);
    mip_.sendto((char *)&q, mip_msg_size(q), ha_port);

    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    if (mip_.select_read(timeout) == 0)
      throw packet::recv_timeout("receiving MIP4 RRP");

    struct mip_rrp p;
    size_t len = mip_.recv((char *)&p, sizeof(p));
    verify_rrp(p, len, q);

    return p;
  }
};

} // namespace rfc3344

#endif
