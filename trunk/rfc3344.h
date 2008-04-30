/*
 * http://tools.ietf.org/html/rfc1256
 */

#ifndef PMIP_RFC3344_H
#define PMIP_RFC3344_H

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
#define MIPCODE_BAD_FORMAT 134
#define MIPCODE_BAD_HA     136

struct ra_ext_hdr {
	unsigned char type;
	unsigned char length;
};

struct ra_ext_magent_adv {
	unsigned short sequence;
	unsigned short lifetime;
	union {
		struct {
			unsigned char flag_T:1;
			unsigned char flag_r:1;
			unsigned char flag_G:1;
			unsigned char flag_M:1;
			unsigned char flag_F:1;
			unsigned char flag_H:1;
			unsigned char flag_B:1;
			unsigned char flag_R:1;
		};
		unsigned char flags;
	};
	unsigned char reserved;
} __attribute__((packed));

struct mip_ext_auth {
	unsigned char type;
	unsigned char length;
	unsigned long spi;
	char auth[MIP_AUTH_MAX];
} __attribute__((packed));

struct mip_reg_request {
	unsigned char type;
	union {
		struct {
			unsigned char flag_x:1;
			unsigned char flag_T:1;
			unsigned char flag_r:1;
			unsigned char flag_G:1;
			unsigned char flag_M:1;
			unsigned char flag_D:1;
			unsigned char flag_B:1;
			unsigned char flag_S:1;
		};
		unsigned char flags;
	};
	unsigned short lifetime;
	unsigned long hoa;
	unsigned long ha;
	unsigned long coa;
	unsigned long long id;
	struct mip_ext_auth auth;
} __attribute__((packed));

struct mip_reg_reply {
	unsigned char type;
	unsigned char code;
	unsigned short lifetime;
	unsigned long hoa;
	unsigned long ha;
	unsigned long long id;
	struct mip_ext_auth auth;
} __attribute__((packed));

unsigned long long time_stamp();

#endif
