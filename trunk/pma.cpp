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

#define PMA_SERVER_SOCK "/var/run/proxymip4-pma.sock"
#define PMA_CLIENT_SOCK "/tmp/proxymip4-pma-client.sock"

using namespace std;
using namespace boost;
using namespace rfc3344;
using namespace bcache;
using namespace sockpp;

char *progname;

static void usage()
{
  fprintf(stderr, "\
Usage: %s -d\n\
       %s -m <hoa> -c <coa> -h <ha> -s <spi> -i <if> -l <life> -f\n\
  -d   start pma daemon\n\
  -m   register home address 'hoa'\n\
  -r   remove socket file if needed\n\
  -c   using care-of address 'coa'\n\
  -h   register with home agent 'ha'\n\
  -l   lifetime, default to 0xfffe\n\
  -i   link 'if' which mn reside\n\
  -s   spi index for regstration\n",
     progname, progname);
  exit(-1);
}

struct pma_msg {
  int code;
  in_addr_t hoa;
  in_addr_t ha;
  in_addr_t coa;
  __u32 spi;
  __u16 lifetime;
  char ifname[10];
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

  void send(pma_msg const &msg) {
    sendto_ex(fd_, &msg, sizeof(msg), 0, (struct sockaddr *)&remote_, sizeof(remote_));
  }

  int select_read(timeval &tv) const {
    fd_set rfds;

    FD_ZERO(&rfds);
    FD_SET(fd_, &rfds);

    return select_ex(fd_ + 1, &rfds, NULL, NULL, &tv);
  }

  pma_msg recv() {
    pma_msg msg;
    socklen_t len = sizeof(remote_);
    recvfrom_ex(fd_, &msg, sizeof(msg), 0, (struct sockaddr *)&remote_, &len);
    return msg;
  }

  ~pma_unix() {
    close_ex(fd_);
    unlink_ex(flocal_);
  }
};

volatile int exiting = 0;

void signal_handler(int signo)
{
  syslog(LOG_INFO, "received signal no: %d, stopping %s daemon", signo, progname);
  exiting = 1;
}

void pma_daemon()
{
  try {
    daemonize(progname, signal_handler);
    openlog(progname, 0, LOG_DAEMON);

    pma_socket pmagent;
    pma_bcache bc;
    pma_unix un(PMA_SERVER_SOCK);
    syslog(LOG_INFO, "started %s daemon\n", progname);
    
    while(!exiting)
    {
      pma_msg m;
      try {
        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        if (un.select_read(tv) == 0)
          continue;
      }
      catch (exception &e) {
        syslog(LOG_ERR, "error: %s\n", e.what());
	break;
      }

      try {
        m = un.recv();
        syslog(LOG_INFO, "sending MIP4 RRQ for MN %08x with lifetime %hu\n", m.hoa, m.lifetime);
    
        struct mip_rrp p = pmagent.request(m.hoa, m.ha, m.coa, m.spi, m.lifetime);
        if (p.code == MIPCODE_ACCEPT) 
	{
          bc.register_mif(m.hoa, m.ifname);
          if (m.lifetime == 0) 
            bc.deregister_binding(m.hoa);
          else 
            bc.register_binding(m.hoa, m.ha, m.coa, m.spi, m.lifetime);
        }
        m.code = p.code;
	un.send(m);
      }
      catch (exception &e) {
        syslog(LOG_ERR, "error sending MIP4 RRQ: %s\n", e.what());
	m.code = -1;
	un.send(m);
      }
    }
  }
  catch (exception &e) {
    syslog(LOG_ERR, "error initializing daemon: %s\n", e.what());
  }

  if (exiting == 0)
    exit(-1);

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

    pma_msg m;
    m.code = 0;
    m.ha = ha;
    m.hoa = hoa;
    m.coa = coa;
    m.spi = spi;
    m.lifetime = lifetime;
    strncpy(m.ifname, ifname, 10);

    un.send(m);
    pma_msg n = un.recv();
    fprintf(stderr, "reply code = %d\n", n.code);
  }
  catch (exception &e) {
    fprintf(stderr, "%s\n", e.what());
  }

  return 0;
}
