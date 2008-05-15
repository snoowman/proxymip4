#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <map>
#include <openssl/hmac.h>
#include "posixpp.hpp"
#include "common.hpp"
#include "sadb.hpp"
#include "rfc3344.hpp"
#include "config.hpp"

using namespace std;
using namespace rfc3344;

namespace sadb {

typedef map<__u32, mipsa> sadb_t;
sadb_t sadb;

void flush_sadb()
{
  sadb.clear();
}

void load_sadb()
{
  FILE *fp = fopen(MIPSADB_CONF, "r");
  if (fp == NULL)
    return;

  sadb.clear();
  while(!feof(fp)) {
    mipsa sa;
    if (scan_sa(fp, &sa) == -1) {
      break;
    }
    sadb[sa.spi] = sa;
  }
  fclose_ex(fp);
}

void save_sadb()
{
  FILE *fp = fopen_ex(MIPSADB_CONF, "w");

  sadb_t::iterator i;
  for (i = sadb.begin(); i != sadb.end(); ++i) {
    print_sa(fp, &i->second);
  }
  fclose_ex(fp);
}

struct mipsa *find_sa(__u32 spi)
{
  sadb_t::iterator i = sadb.find(spi);

  if (i == sadb.end())
    return NULL;
  else
    return &i->second;
}

void add_sa(__u32 spi, char *secret, char *hmac, unsigned int replay, unsigned int delay)
{
  if (spi < 256)
    throw bad_spi();

  sadb_t::iterator i = sadb.find(spi);
  if (i == sadb.end()) {
    sadb[spi] = mipsa();
    i = sadb.find(spi);
    i->second.spi = spi;
  }

  i->second.secret = secret;
  i->second.hmac =  hmac;
  i->second.replay = replay;
  i->second.delay = delay;
}

bool del_sa(__u32 spi)
{
  if (sadb.find(spi) == sadb.end())
    return false;
  sadb.erase(spi);
  return true;
}

void list_sa(__u32 spi)
{
  if (spi == 0) {
    sadb_t::iterator i = sadb.find(spi);
    for (i = sadb.begin(); i != sadb.end(); ++i)
      print_sa(stdout, &i->second);
  }
  else {
    struct mipsa *sa = find_sa(spi);
    if (sa)
      print_sa(stdout, sa);
    else
      printf("no spi (%u) found in sadb\n", spi);
  }
}

void print_sa(FILE *fp, struct mipsa *sa)
{
  char *replay;
  if (sa->replay == MIPSA_REPLAY_NONCE)
    replay = "nonce";
  else if (sa->replay == MIPSA_REPLAY_TIMESTAMP)
    replay = "timestamp";
  else
    replay = "badreplay";

  fprintf(fp, "spi:%u hmac:%s secret:%s replay:%s delay:%u\n", sa->spi, sa->hmac.c_str(), sa->secret.c_str(), replay, sa->delay);
}

int scan_sa(FILE *fp, struct mipsa *sa)
{
  char replay[20];
  char hmac[20];
  char secret[100];

  int ret = fscanf(fp, "spi:%u hmac:%20s secret:%100s replay:%20s delay:%u\n", &sa->spi, hmac, secret, replay, &sa->delay);
  if (ret == 0 || ret == EOF)
    return -1;
  else if (ret != 5)
    throw bad_sadb();
  if (sa->spi < 256)
    throw bad_spi();

  sa->hmac = hmac;
  sa->secret = secret;
  if (strcmp(replay, "timestamp") == 0)
    sa->replay = MIPSA_REPLAY_TIMESTAMP;
  else if (strcmp(replay, "nonce") == 0)
    sa->replay = MIPSA_REPLAY_NONCE;
  else
    sa->replay = MIPSA_REPLAY_TIMESTAMP;
  return 0;
}

int rfc2104_hmac(char const *mdname, char const *key, int klen, void const *m, int mlen, char *md, unsigned int max_md_len)
{
	static bool initialized = false;
	if (!initialized) {
		initialized = true;
		OpenSSL_add_all_algorithms();
	}

	unsigned int ret = max_md_len;
	EVP_MD const *alg = EVP_get_digestbyname(mdname);
	if (!alg)
		return 0; // should I throw?

	HMAC(alg, key, klen, (unsigned char const *)m, mlen, (unsigned char *)md, &ret);
	return ret;
}

int sa_auth(char *auth, int authlen, void const *buf, ssize_t len, struct mipsa *sa)
{
  char const *md = sa->hmac.c_str();
  char const *pass = sa->secret.c_str();
  int passlen = sa->secret.length();
  return rfc2104_hmac(md, pass, passlen, buf, len, auth, authlen);
}

int sa_verify(char const *old_auth, int old_authlen, void const *buf, ssize_t len, struct mipsa *sa)
{
  const int MAX_AUTH = 100;
  char auth[MAX_AUTH];

  int authlen = sa_auth(auth, MAX_AUTH, buf, len, sa);
  if (authlen != old_authlen)
    return 0;

  if (memcmp(auth, old_auth, authlen - 4) == 0)
    return 1;
  return 0;
}

ssize_t sa_authlen(struct mipsa *sa)
{
  const int MAX_AUTH = 100;
  char auth[MAX_AUTH];

  char c = 0;
  ssize_t ret = sa_auth(auth, MAX_AUTH, &c, sizeof(c), sa);
  return ret;
}

} // namespace sadb
