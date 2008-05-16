#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <syslog.h>
#include <exception>
#include <boost/lexical_cast.hpp>
#include "common.hpp"
#include "rfc3344.hpp"
#include "sadb.hpp"
#include "sockpp.hpp"
#include "bcache.hpp"
#include "packet.hpp"
#include "network.hpp"
#include "config.hpp"

using namespace std;
using namespace boost;
using namespace rfc3344;
using namespace bcache;
using namespace sockpp;
using namespace sadb;

struct mip_info {
  int       errcode;
  char      ifname[IFNAMSIZ];
  __u16     lifetime;
  __u32     spi;
  __u64     id;
  in_addr_t hoa;
  in_addr_t ha;
  in_addr_t coa;
  in_addr_t homecn[HOMECN_MAX];
  int       num_homecn;
};

class pma_socket {
  sockpp::udp_socket mip_;

private:
  int create_request(char *buf, int buflen, mip_info &info)
  {
    sadb::mipsa *sa = sadb::find_sa(info.spi);
    if (!sa)
      throw sadb::invalid_spi();

    bzero(buf, buflen);
    char *p = buf;

    /* fill in request header first */
    struct miprequest_hdr *req = (struct miprequest_hdr *)p;
    req->type = MIPTYPE_REQUEST;
    req->lifetime = htons(info.lifetime);
    req->hoa      = info.hoa;
    req->ha       = info.ha;
    req->coa      = info.coa;
    req->id       = htonll(time_stamp());
    info.id       = req->id;
    /* request for reverse tunnel */
    req->flag_T = 1; 
    p += sizeof(*req);

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
    if (!info.lifetime) {
      struct pmip_skip *skip = (struct pmip_skip *)p;
      skip->type = MIPEXT_PMIPSKIP;
      skip->subtype = PMIPSKIP_HOMECN;
      p += sizeof(*skip);

      /* add ha address */
      memcpy(p, &info.ha, 4);
      in_addr_t *homecn = (in_addr_t *)(p + 4);
      int num_addr = 1 + load_neigh(homecn, HOMECN_MAX, info.ifname, info.hoa);
      skip->length  = 1 + 4 * num_addr;
      p += 4 * num_addr;
    }

    /* or add mobile dev id extension */
    mac_addr mac;
    if (get_mac(&mac, info.hoa, info.ifname)){
      struct pmip_skip *skip =  (struct pmip_skip *)p;
      skip->type = MIPEXT_PMIPSKIP;
      skip->subtype = PMIPSKIP_DEV;
      skip->length  = 8;
      p += sizeof(*skip);

      __u8 *pidtype = (__u8 *)p;
      *pidtype = PMIPDEV_MAC;
      p += 1;
  
      memcpy(p, &mac, 6);
      p += 6;
    }

    /* add FA HA auth*/
    struct mip_auth *auth = (struct mip_auth *)p;
    auth->type = MIPEXT_FHAUTH;
    auth->spi = htonl(info.spi);
    auth->length = 4;
    p += sizeof(*auth);

    int authlen = sa_authlen(sa);
    auth->length += authlen;
    sa_auth(p, authlen, buf, p - buf, sa);
    p += authlen;

    if (p - buf > buflen)
      throw packet::invalid_length();
    return p - buf;
  }

  void auth_reply(char const *auth, int authlen, char const *buf, int len, mip_info &info)
  {
    sadb::mipsa *sa = sadb::find_sa(info.spi);
    if (!sa)
      throw packet::bad_packet("incorrect spi");

    if (authlen != sa_authlen(sa))
      throw packet::bad_packet("incorrect auth length");

    if (!sa_verify(auth, authlen, buf, len, sa))
      throw packet::bad_packet("authentication failed");
  }

  void verify_reply(char const *buf, int len, mip_info &info)
  {
    char const *p = buf;

    /* verify MIP header first */
    struct mipreply_hdr *rep= (struct mipreply_hdr *)p;
    p += sizeof(*rep);
    if (p - buf > len)
      throw packet::bad_packet("bad MIP header");
    if (rep->type != MIPTYPE_REPLY)
      throw packet::bad_packet("bad MIP type");
    if (info.hoa != rep->hoa)
      throw packet::bad_packet("incorrect home address");
    if (info.ha  != rep->ha)
      throw packet::bad_packet("incorrect care-of address");
    if (info.id != rep->id)
      throw packet::bad_packet("incorrect id");
  
    /* MN HA auth is expected, normally */
    int expect_mhauth = 1;
    /* FA HA auth is not expected */
    int expect_fhauth = 0;

    /* search for extension */
    while (p - buf < len) {
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
  
          info.spi = ntohl(authext->spi);
          int authlen = authext->length - 4;
          char const *auth = p;
          auth_reply(auth, authlen, buf, p - buf, info);
          p += authlen;
	}
        break;

      case MIPEXT_PMIPSKIP:
        {
          struct pmip_skip *skip = (struct pmip_skip *)p;
          p += sizeof(*skip);
          if (skip->subtype != PMIPSKIP_HOMECN) {
            /* other skippable subtype are skipped by PMA */
            syslog(LOG_WARNING, "skipping proxy mip4 extension %hhd", skip->subtype);
	  }
	  else if ((skip->length - 1) % sizeof(in_addr_t) != 0) {
            syslog(LOG_WARNING, "invalid homecn length %hhd, ignored", skip->length);
	  }
	  else {
	    int num_addr = (skip->length - 1) / sizeof(in_addr_t);
	    info.num_homecn = num_addr;
            memcpy(info.homecn, p, num_addr * sizeof(in_addr_t));
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
            throw packet::bad_packet("unknown non-skippable subtype");
          }
          else if (nonskip->method != PMIPAUTH_FAHA) {
            throw packet::bad_packet("unknown non-skippable method");
          }
          else {
            /* set expect FA HA auth, not MN HA now */
            expect_fhauth = 1;
	    expect_mhauth = 0;
          }
	}
        break;

      default:
        throw packet::bad_packet("unsupported extension");
      }
    }

    /* verify packet are authenticated */
    if (expect_mhauth)
      throw packet::bad_packet("expecting MN HA auth extension");
    if (expect_fhauth)
      throw packet::bad_packet("expecting FA HA auth extension");

    /* verify no gabbage in packet */
    if (p - buf != len)
      throw packet::bad_packet("incorrect packet length");

    /* store MIP code to info */
    info.errcode = rep->code;
  }

public:
  pma_socket() {
    sadb::load_sadb();
    randomize();
    mip_.reuse_addr();
  }

  void request(mip_info &info) {
    /* rebind to CoA address */
    sockpp::in_address coa_port(info.coa);
    mip_.rebind(coa_port);

    /* create and send request to HA addr */
    char buf[packet::MTU];
    int len = create_request(buf, packet::MTU, info);
    sockpp::in_address ha_port(info.ha, MIPPORT);
    mip_.sendto(buf, len, ha_port);

    /* wait for 1 second */
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    if (mip_.select_read(timeout) == 0)
      throw packet::recv_timeout("receiving MIP4 RRP");

    /* verify response */
    char reply_buf[packet::MTU];
    len = mip_.recv(reply_buf, packet::MTU);

    verify_reply(reply_buf, len, info);
  }
};

class pma_unix {
  int fd_;
  char const *flocal_;
  struct sockaddr_un local_;
  struct sockaddr_un remote_;

public:
  pma_unix(char const *flocal) {
    fd_ = socket_ex(AF_UNIX, SOCK_DGRAM, 0);
    flocal_ = flocal;

    bzero(&local_, sizeof(local_));
    local_.sun_family = AF_UNIX;
    strcpy(local_.sun_path, flocal);
    bind_ex(fd_, (struct sockaddr *)&local_, sizeof(local_));
  }

  void set_remote(char const *fremote) {
    bzero(&remote_, sizeof(remote_));
    remote_.sun_family = AF_UNIX;
    strcpy(remote_.sun_path, fremote);
  }

  void send(mip_info const &msg) {
    sendto_ex(fd_, &msg, sizeof(msg), 0, (struct sockaddr *)&remote_, sizeof(remote_));
  }

  void send_code(int errcode) {
    sendto_ex(fd_, &errcode, sizeof(errcode), 0, (struct sockaddr *)&remote_, sizeof(remote_));
  }

  int select_read(timeval &tv) const {
    fd_set rfds;

    FD_ZERO(&rfds);
    FD_SET(fd_, &rfds);

    return select_ex(fd_ + 1, &rfds, NULL, NULL, &tv);
  }

  mip_info recv() {
    mip_info msg;
    socklen_t len = sizeof(remote_);
    recvfrom_ex(fd_, &msg, sizeof(msg), 0, (struct sockaddr *)&remote_, &len);
    return msg;
  }

  int recv_code() {
    int ret;
    socklen_t len = sizeof(remote_);
    recvfrom_ex(fd_, &ret, sizeof(ret), 0, (struct sockaddr *)&remote_, &len);
    return ret;
  }

  ~pma_unix() {
    close_ex(fd_);
    unlink_ex(flocal_);
  }
};

static char const *progname;

static void usage()
{
  fprintf(stderr, "\
Usage: %s -d\n\
       %s -m <hoa> -c <coa> -h <ha> -s <spi> -i <if> -l <life> -f\n\
  -d   start pma daemon\n\
  -m   register home address 'hoa'\n\
  -c   using care-of address 'coa'\n\
  -h   register with home agent 'ha'\n\
  -r   remove socket file if needed\n\
  -l   lifetime, default to 0xfffe\n\
  -i   link 'if' which mn reside\n\
  -s   spi index for regstration\n",
     progname, progname);
  exit(-1);
}

int handle_signal(volatile int *psigno)
{
  int exiting = 0;

  switch(*psigno) {
  case 0:
    return exiting;

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

void pma_daemon()
{
  try {
    volatile int signo = 0;
    daemonize(progname, &signo);

    pma_socket pmagent;
    pma_bcache bc;
    pma_unix un(PMA_SERVER_SOCK);
    syslog(LOG_INFO, "started %s daemon\n", progname);
    
    while(1)
    {
      if (handle_signal(&signo)) // should we exit?
        break;

      mip_info info;
      struct timeval tv;
      tv.tv_sec = 1;
      tv.tv_usec = 0;

      try {
        if (un.select_read(tv) == 0)
          continue;
      }
      catch (exception &) {
        syslog(LOG_WARNING, "syscall 'select' interrupted");
	continue;
      }

      try {
        info = un.recv();
        syslog(LOG_INFO, "sending MIP4 RRQ for MN %08x with lifetime %hu\n", info.hoa, info.lifetime);
    
        pmagent.request(info);
        if (info.errcode == MIPCODE_ACCEPT) 
	{
          bc.store_mif(info.hoa, info.ifname);
	  bc.store_homecn(info.homecn, info.num_homecn);
          bc.update_binding(info.hoa, info.ha, info.coa, info.lifetime);
        }
	un.send_code(info.errcode);
      }
      catch (exception &e) {
        syslog(LOG_ERR, "error sending MIP4 RRQ: %s\n", e.what());
	un.send_code(-1);
      }
    }
  }
  catch (exception &e) {
    syslog(LOG_ERR, "error initializing daemon: %s\n", e.what());
    closelog();
    exit(-1);
  }

  syslog(LOG_INFO, "exited %s daemon gracefully\n", progname);
  closelog();
  exit(0);
}

int main(int argc, char **argv)
{
  progname = parse_progname(argv[0]);

  in_addr_t hoa = 0;
  in_addr_t ha = 0;
  in_addr_t coa = 0;
  char *ifname = NULL;
  __u32 spi = 0;
  __u16 lifetime = 0xfffe;
  bool daemon = false;
  bool remove = false;

  try {
    char c;
    while ((c = getopt(argc, argv, "h:m:c:s:l:i:dr")) != -1) {
      switch (c) {
      case 'h':
        ha = in_address(optarg).to_u32();
        break;
      case 'm':
        hoa = in_address(optarg).to_u32();
        break;
      case 'c':
        coa = in_address(optarg).to_u32();
        break;
      case 'i':
        ifname = optarg;
        break;
      case 'l':
        lifetime = lexical_cast<__u16>(optarg);
        break;
      case 's':
        spi =  lexical_cast<__u32>(optarg);
        break;
      case 'd':
        daemon = true;
	break;
      case 'r':
        remove = true;
	break;
      default:
        usage();
      }
    }
  }
  catch (exception &e) {
    fprintf(stderr, "%s %s\n", e.what(), optarg);
  }

  if (argc == 1)
    usage();

  if (daemon) {
    if (remove)
      unlink(PMA_SERVER_SOCK);
    pma_daemon();
  }

  if (ha == 0 || hoa == 0 || coa == 0 || spi == 0 || ifname == NULL)
    usage();

  try {
    if (remove)
      unlink(PMA_CLIENT_SOCK);
    pma_unix un(PMA_CLIENT_SOCK);
    un.set_remote(PMA_SERVER_SOCK);

    mip_info m;
    bzero(&m, sizeof(m));

    m.errcode = 0;
    m.ha = ha;
    m.hoa = hoa;
    m.coa = coa;
    m.spi = spi;
    m.lifetime = lifetime;
    strncpy(m.ifname, ifname, IFNAMSIZ - 1);

    un.send(m);

    struct timeval tv;
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    if (un.select_read(tv) == 0)
      throw packet::recv_timeout("receiving from UNIX socket");

    int errcode = un.recv_code();
    fprintf(stderr, "reply code = %d\n", errcode);
  }
  catch (exception &e) {
    fprintf(stderr, "%s\n", e.what());
  }

  return 0;
}
