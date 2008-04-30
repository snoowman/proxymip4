#ifndef MIP_SADB_H
#define MIP_SADB_H

#include <stdio.h>
#include <netinet/in.h>

#define MIPSA_MAXSEC 80
#define MIPSA_MAXALG 10
#define MIPSA_MAXSA  1024

enum {
	MIPSA_REPLAY_TIMESTAMP,
	MIPSA_REPLAY_NONCE,
};

struct mipsa {
	__u32 spi;
	char secret[MIPSA_MAXSEC];
	char hmac[MIPSA_MAXALG];
	unsigned int replay;
	unsigned int delay;
	struct mipsa *next;
};

void load_sadb();
void save_sadb();
void flush_sadb();
struct mipsa *find_sa(__u32 spi);

int add_sa(__u32 spi, char *secret, char *hmac, unsigned int replay, unsigned int delay);
int del_sa(__u32 spi);
void list_sa(__u32 spi);
void print_sa(FILE* fp, struct mipsa *sa);
int scan_sa(FILE* fp, struct mipsa *sa);

ssize_t authlen_by_sa(struct mipsa *sa);
int auth_by_sa(char *auth, void *buf, ssize_t len, struct mipsa *sa);
int verify_by_sa(char *auth, void *buf, ssize_t len, struct mipsa *sa);
__u64 id_by_sa(struct mipsa *sa);
__u64 rep_id_by_sa(__u64 req_id, struct mipsa *sa, in_addr_t hoa);

#endif
