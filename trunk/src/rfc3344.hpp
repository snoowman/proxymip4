/*
 * http://tools.ietf.org/html/rfc3344
 */

#ifndef PMIP_RFC3344_HPP
#define PMIP_RFC3344_HPP

#include <asm/types.h>
#include <netinet/in.h>

//#include <map>
//#include <stdio.h>
//#include <syslog.h>
//#include "rfc1256.hpp"
//#include "sockpp.hpp"
//#include "packet.hpp"
//#include "sadb.hpp"

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

} // namespace rfc3344

#endif
