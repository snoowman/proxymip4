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

using namespace std;
using namespace sockpp;
using namespace rfc3344;
using namespace sadb;
using namespace bcache;

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
    
    if (abs((long)t1 - (long)t2) > (long)sa->delay) {
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
      catch (exception &e) {
        syslog(LOG_WARNING, "error ignored: %s", e.what());
	continue;
      }

      struct mip_rrq q;
      in_address from;

      int errcode = hagent.recv(q, from);
      hagent.reply(errcode, q, from);

      if (errcode != rfc3344::MIPCODE_ACCEPT)
        continue;

      if (q.lifetime == 0)
        bc.deregister_binding(q.hoa);
      else
        bc.register_binding(q.hoa, q.ha, q.coa, q.auth.spi, q.lifetime);
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

