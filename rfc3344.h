/*
 * http://tools.ietf.org/html/rfc1256
 */

#ifndef PMIP_RFC3344_H
#define PMIP_RFC3344_H

#include <asm/types.h>
#include <netinet/in.h>

#define RA_MOBILITY_AGENT_EXTENTION_TYPE 16
#define RA_PREFIX_LENGTHS_EXTENTION_TYPE 19
#define MIP_UDP_PORT 434
#define MIP_REQUEST_TYPE  1
#define MIP_REPLY_TYPE 3
#define MIPEXT_AUTH_TYPE 32
#define MIP_AUTH_MAX 255
#define MIP_MSG_SIZE1(req) (sizeof((req)) - MIP_AUTH_MAX)
#define MIP_MSG_SIZE2(req) (sizeof((req)) - MIP_AUTH_MAX + (req).auth.length - 4)

#define MIPCODE_ACCEPT     0 
#define MIPCODE_BAD_AUTH   131
#define MIPCODE_BAD_ID     133
#define MIPCODE_BAD_FORMAT 134
#define MIPCODE_BAD_HA     136

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

struct mip_reg_request {
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

struct mip_reg_reply {
	__u8 type;
	__u8 code;
	__u16 lifetime;
	in_addr_t hoa;
	in_addr_t ha;
	__u64 id;
	struct mip_ext_auth auth;
} __attribute__((packed));

__u64 time_stamp();
__u64 nonce();

#endif
