#ifndef PMIP_SADB_H
#define PMIP_SADB_H

#include <stdio.h>
#include <netinet/in.h>
#include <string>
#include <stdexcept>

namespace sadb{

enum {
	MIPSA_REPLAY_TIMESTAMP,
	MIPSA_REPLAY_NONCE,
};

struct mipsa {
	__u32 spi;
	std::string secret;;
	std::string hmac;
	unsigned int replay;
	unsigned int delay;
};

void load_sadb();
void save_sadb();
void flush_sadb();
struct mipsa *find_sa(__u32 spi);

void add_sa(__u32 spi, char *secret, char *hmac, unsigned int replay, unsigned int delay);
bool del_sa(__u32 spi);
void list_sa(__u32 spi);
void print_sa(FILE *fp, struct mipsa *sa);
int scan_sa(FILE *fp, struct mipsa *sa);

ssize_t sa_authlen(struct mipsa *sa);
int sa_auth(char *auth, int authlen, void const *buf, ssize_t len, struct mipsa *sa);
int sa_verify(char const *auth, int authlen, void const *buf, ssize_t len, struct mipsa *sa);

class bad_spi : public std::range_error {
public:
  bad_spi()
    : range_error("spi 0-255 are reserved")
  { }
};

class invalid_spi : public std::range_error {
public:
  invalid_spi()
    : range_error("spi not exist")
  { }
};

class bad_sadb : public std::runtime_error {
public:
  bad_sadb()
    : runtime_error("bad sadb format")
  { }
};

} // namespace sadb

#endif
