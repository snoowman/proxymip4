/*
 * http://tools.ietf.org/html/rfc3344
 * http://tools.ietf.org/html/draft-leung-mip4-proxy-mode-08
 */

#ifndef PMIP_RFC3344_HPP
#define PMIP_RFC3344_HPP

#include <asm/types.h>
#include <netinet/in.h>

namespace rfc3344 {

/* RFC3344 defines */
int const RAEXT_MOBIAGENT = 16;
int const RAEXT_PREFLEN = 19;

int const MIPPORT = 434;
int const MIPTYPE_REQUEST = 1;
int const MIPTYPE_REPLY   = 3;
int const MIPEXT_MHAUTH  = 32;
int const MIPEXT_MFAUTH  = 33;
int const MIPEXT_FHAUTH  = 34;

int const MIPCODE_ACCEPT    = 0;
int const MIPCODE_ACCESS = 129;
int const MIPCODE_MNAUTH = 131;
int const MIPCODE_FAAUTH = 131;
int const MIPCODE_ID     = 133;
int const MIPCODE_FORMAT = 134;
int const MIPCODE_HA     = 136;

/* Proxy Mobile IPv4 defines */

/* non-skippable extension */
int const MIPEXT_PMIPNOSK = 47;
/* skippable extension */
int const MIPEXT_PMIPSKIP = 147;
/* per-node auth subtype for skippable ext */
int const PMIPNOSK_AUTH    = 1;
/* interface id subtype for non-skippable ext */
int const PMIPSKIP_IFACE   = 1;
/* device id subtype for non-skippable ext */
int const PMIPSKIP_DEV     = 2;
/* subscriber id subtype for non-skippable ext */
int const PMIPSKIP_SUBS    = 3;

/* method for per-node auth */
int const PMIPAUTH_FAHA    = 1;
int const PMIPAUTH_IPSEC   = 2;

/* id type for device id extension */
int const PMIPDEV_MAC = 1;

/* VM home correspondent nodes extension */
int const PMIPSKIP_HOMECN  = 128;
int const HOMECN_MAX       = 63; /* (255 - 1) /4 */

struct raext_hdr {
  __u8 type;
  __u8 length;
};

struct raext_madv {
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

struct mip_auth {
  __u8 type;
  __u8 length;
  __u32 spi;
} __attribute__((packed));

/*
 * nonskip extension defined in pmip4 draft is kind of stupid
 * so I decide to change it to a non-stupid version
 */

/* this is draft version */
#if 0
struct pmip_nonskip {
  __u8  type;
  __u8  subtype;
  __u16 length;
  __u8  method;
} __attribute__((packed));
#endif

/* non-draft version */
struct pmip_nonskip {
  __u8  type;
  __u8  length;
  __u8  subtype;
  __u8  method;
} __attribute__((packed));

struct pmip_skip {
  __u8 type;
  __u8 length;
  __u8 subtype;
} __attribute__((packed));

struct miprequest_hdr {
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
} __attribute__((packed));

struct mipreply_hdr {
  __u8 type;
  __u8 code;
  __u16 lifetime;
  in_addr_t hoa;
  in_addr_t ha;
  __u64 id;
} __attribute__((packed));

} // namespace rfc3344

#endif
