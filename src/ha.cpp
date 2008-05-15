#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <exception>
#include "common.hpp"
#include "rfc3344.hpp"
#include "sadb.hpp"
#include "sockpp.hpp"
#include "bcache.hpp"
#include "packet.hpp"
#include "network.hpp"

using namespace std;
using namespace sockpp;
using namespace rfc3344;
using namespace sadb;
using namespace bcache;

struct request_info {
  int       errcode;
  __u16     lifetime;
  __u32     spi;
  __u64     id;
  in_addr_t hoa;
  in_addr_t ha;
  in_addr_t coa;
  in_addr_t homecn[HOMECN_MAX];
  int       num_homecn;
};

class ha_socket {
  sockpp::udp_socket mip_;
  sockpp::in_iface const &homeif_;
  std::map<__u32, __u64> lastid_;

private:
  int create_reply(char *buf, int buflen, request_info const &info)
  {
    bzero(buf, buflen);
    char *p = buf;

    /* fill MIP4 header fields */
    struct mipreply_hdr *rep = (struct mipreply_hdr *)p;
    rep->type     = MIPTYPE_REPLY;
    rep->code     = info.errcode;
    rep->lifetime = info.lifetime;
    rep->hoa      = info.hoa;
    rep->ha       = info.ha;
    rep->id       = info.id;
    p += sizeof(*rep);
  
    /* add PMIP4 per-node auth extension */
    struct pmip_nonskip *nonskip = (struct pmip_nonskip *)p;
    nonskip->type    = MIPEXT_PMIPNOSK;
    nonskip->subtype = PMIPNOSK_AUTH;
    nonskip->method  = PMIPAUTH_FAHA;

    /*
     * in pmip4 draft version, length are u16, so the following line would be
     *   nonskip->length  = htons(1);
     * but I decide to use u8 instead, bit me
     */
    nonskip->length  = 2;
    p += sizeof(*nonskip);

    /* if needed, add homecn extension */
    if (info.lifetime) {
      struct pmip_skip *skip = (struct pmip_skip *)p;
      skip->type = MIPEXT_PMIPSKIP;
      skip->subtype = PMIPSKIP_HOMECN;
      p += sizeof(*skip);
  
      in_addr_t *homecn = (in_addr_t *)p;
      int num_addr = load_neigh(homecn, HOMECN_MAX, homeif_.name());
      skip->length  = 1 + 4 * num_addr;
      p += 4 * num_addr;
    }

    /* add FA HA auth*/
    struct mip_auth *auth = (struct mip_auth *)p;
    auth->type = MIPEXT_FHAUTH;
    auth->spi = info.spi;
    auth->length = 4;
    p += sizeof(*auth);

    sadb::mipsa *sa = sadb::find_sa(ntohl(info.spi));
    if (!sa) {
      if (p - buf > buflen)
        throw packet::invalid_length();
      return p - buf;
    }
    int authlen = sa_authlen(sa);
    auth->length += authlen;
    sa_auth(p, authlen, buf, p - buf, sa);
    p += authlen;

    if (p - buf > buflen)
      throw packet::invalid_length();
    return p - buf;
  }

  int auth_request(char const *auth, int authlen, char const *buf, int len, request_info &info)
  {
    sadb::mipsa *sa = sadb::find_sa(ntohl(info.spi));
    if (!sa) {
      syslog(LOG_WARNING, "incorrect spi %u\n", ntohl(info.spi));
      return MIPCODE_MNAUTH;
    }

    if (authlen != sa_authlen(sa)) {
      syslog(LOG_WARNING, "incorrect auth length %d", authlen);
      return MIPCODE_FORMAT;
    }

    if (!sa_verify(auth, authlen, buf, len, sa)) {
      syslog(LOG_WARNING, "mobile node failed authentication\n");
      return MIPCODE_MNAUTH;
    }

    __u64 id = ntohll(info.id);
    __u64 t1 = id >> 32;
    __u64 t2 = time_stamp() >> 32;
    
    if (abs((long)t1 - (long)t2) > (long)sa->delay) {
      syslog(LOG_WARNING, "time not synchronized\n");

      // reset id to home agent's time
      id           &= (1LLU << 32) - 1;
      id           |= t2 << 32;
      info.id       = htonll(id);
      return MIPCODE_ID;
    }

    if (lastid_[info.hoa] == 0) {
      lastid_[info.hoa] = id;
    }
    else if (id <= lastid_[info.hoa]) {
      syslog(LOG_WARNING, "identifier smaller than previous one\n");
      return MIPCODE_ID;
    }

    return MIPCODE_ACCEPT;
  }

  request_info verify_request(char const *buf, int len)
  {
    request_info info;
    bzero(&info, sizeof(info));

    info.errcode = MIPCODE_ACCEPT;
    char const *p = buf;

    /* verify MIP header first */
    struct miprequest_hdr *req = (struct miprequest_hdr *)p;
    info.ha       = req->ha;
    info.hoa      = req->hoa;
    info.coa      = req->coa;
    info.lifetime = req->lifetime;
    info.id       = req->id;
    p += sizeof(*req);

    if (p - buf > len) {
      syslog(LOG_WARNING, "bad MIP header\n");
      info.errcode = MIPCODE_FORMAT;
    }
    if (req->type != MIPTYPE_REQUEST) {
      syslog(LOG_WARNING, "incorrect MIP type value %d\n", req->type);
      info.errcode = MIPCODE_FORMAT;
    }
    else if (req->ha != homeif_.addr().to_u32()) {
      syslog(LOG_WARNING, "incorrect home agent address %08x\n", req->ha);
      info.errcode = MIPCODE_HA;
    }

    /* MN HA auth is expected, normally */
    int expect_mhauth = 1;
    /* FA HA auth is not expected */
    int expect_fhauth = 0;

    /* search for extension */
    while (p - buf < len && info.errcode == MIPCODE_ACCEPT) {
      __u8 const *ptype = (__u8 const *)p;

      switch (*ptype) {
      case MIPEXT_MHAUTH:
	expect_mhauth = 0;

      case MIPEXT_FHAUTH:
	if (*ptype == MIPEXT_FHAUTH)
	  expect_fhauth = 0;
        {
          struct mip_auth *authext = (struct mip_auth *)p;
          p += sizeof(*authext);
  
          info.spi = authext->spi;
          int authlen = authext->length - 4;
          char const *auth = p;
          info.errcode = auth_request(auth, authlen, buf, p - buf, info);
          p += authlen;
	}
        break;

      case MIPEXT_PMIPSKIP:
        {
          struct pmip_skip *skip = (struct pmip_skip *)p;
          p += sizeof(*skip);
          if (skip->subtype != PMIPSKIP_HOMECN) {
            /* other skippable subtype are skipped */
            syslog(LOG_WARNING, "skipping proxy mip4 extension %hhd", skip->subtype);
	  }
	  else if ((skip->length - 1) % 4 != 0) {
            syslog(LOG_WARNING, "invalid homecn length %hhd, ignored", skip->length);
	  }
	  else {
	    int num_addr = (skip->length - 1) / 4;
	    info.num_homecn = num_addr;
            memcpy(info.homecn, p, num_addr * 4);
	  }
          p += skip->length - 1;
	}
        break;

      case MIPEXT_PMIPNOSK:
        {
          struct pmip_nonskip *nonskip = (struct pmip_nonskip *)p;
          p += sizeof(*nonskip);

          /*
           * in pmip4 draft version, length are u16, so the following line would be
           *   p += ntohs(nonskip->length) - 1;
           * but I decide to use u8 instead, bit me
           */
          p += nonskip->length - 2;
  
          if (nonskip->subtype != PMIPNOSK_AUTH) {
            syslog(LOG_WARNING, "unknown non-skippable subtype %hhd\n", nonskip->subtype);
            info.errcode = MIPCODE_FORMAT;
          }
          else if (nonskip->method != PMIPAUTH_FAHA) {
            syslog(LOG_WARNING, "unknown non-skippable method %hhd\n", nonskip->method);
            info.errcode = MIPCODE_FORMAT;
          }
          else {
            /* set expect FA HA auth, not MN HA now */
            expect_fhauth = 1;
	    expect_mhauth = 0;
          }
	}
        break;

      default:
        syslog(LOG_WARNING, "unsupported extension %hhd\n", *ptype);
        info.errcode = MIPCODE_FORMAT;
      }
    }

    if (info.errcode != MIPCODE_ACCEPT)
      return info;

    if (expect_mhauth) {
      syslog(LOG_WARNING, "expecting MN HA auth extension\n");
      info.errcode = MIPCODE_MNAUTH;
    }
    if (expect_fhauth) {
      syslog(LOG_WARNING, "expecting FA HA auth extension\n");
      info.errcode = MIPCODE_FAAUTH;
    }
    return info; 
  }

public:
  ha_socket(sockpp::in_iface const &homeif)
    : homeif_(homeif)
  {
    sockpp::in_address src_addr(INADDR_ANY, MIPPORT);
    mip_.bind(src_addr);
    sadb::load_sadb();
  }

  int select_read(struct timeval &tv) {
    return mip_.select_read(tv);
  }

  request_info accept_request() {
    /* recv message */
    sockpp::in_address from;
    char buf[packet::MTU];
    size_t len = mip_.recvfrom(buf, packet::MTU, from);

    /* verify request */
    request_info info = verify_request(buf, len);

    /* send reply */
    char reply_buf[packet::MTU];
    len = create_reply(reply_buf, packet::MTU, info);
    mip_.sendto(reply_buf, len, from);

    return info;
  }
};

static char const *progname;

static void usage()
{
  fprintf(stderr, "Usage: %s -i <iface>\n\
  -i   start mobile home agent on link 'iface'\n", 
     progname);
  exit(-1);
}

int handle_signal(volatile int *psigno)
{
  int exiting = 0;

  switch(*psigno) {
  case 0:
    break;

  case SIGUSR1:
    bcache::generic_bcache::list_binding(progname);
    break;

  case SIGHUP:
    sadb::load_sadb();
    break;

  default:
    syslog(LOG_INFO, "received signal no: %d, stopping %s daemon", *psigno, progname);
    exiting = 1;
  }

  *psigno = 0;
  return exiting;
}

int main(int argc, char** argv)
{
  progname = parse_progname(argv[0]);

  char *ifname = NULL;
  char c;
  while ((c = getopt(argc, argv, "i:")) != -1) {
    switch (c) {
    case 'i':
      ifname = optarg;
      break;
    default:
      usage();
    }
  }

  if (argc == 1 || ifname == NULL)
    usage();
  
  try {
    in_iface homeif(ifname);
    ha_socket hagent(homeif);
    ha_bcache bc(homeif);
  }
  catch(exception &e) {
    fprintf(stderr, "%s\n", e.what());
    return -1;
  }

  try {
    volatile int signo = 0;
    daemonize(progname, &signo);

    in_iface homeif(ifname);
    syslog(LOG_INFO, "start %s daemon on HA address %s", progname, homeif.addr().to_string());

    ha_socket hagent(homeif);
    ha_bcache bc(homeif);

    while(1) {
      if (handle_signal(&signo))
        break;

      struct timeval tv;
      tv.tv_sec = 1;
      tv.tv_usec = 0;

      try {
        if (hagent.select_read(tv) == 0)
          continue;
      }
      catch (exception &) {
        syslog(LOG_WARNING, "syscall 'select' interrupted");
	continue;
      }

      struct request_info info = hagent.accept_request();
      if (info.errcode != rfc3344::MIPCODE_ACCEPT)
        continue;

      if (info.lifetime == 0) {
        bc.store_homecn(info.homecn, info.num_homecn);
        bc.deregister_binding(info.hoa);
      }
      else {
        bc.register_binding(info.hoa, info.ha, info.coa, info.lifetime);
      }
    }
  }
  catch(exception &e) {
    syslog(LOG_ERR, "%s", e.what());
    closelog();
    return -1;
  }

  syslog(LOG_INFO, "exited %s daemon gracefully", progname);
  closelog();
  return 0;
}

