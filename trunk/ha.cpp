#include <getopt.h>
#include <math.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <exception>
#include "common.hpp"
#include "rfc3344.hpp"
#include "sadb.hpp"
#include "packet.hpp"
#include "bcache.hpp"

using namespace std;
using namespace sockpp;
using namespace rfc3344;
using namespace sadb;
using namespace bcache;

char *progname;

ha_bcache *pbc = NULL;

static void usage()
{
  fprintf(stderr, "Usage: %s -i <iface>\n\
  -i   start mobile home agent on link 'iface'\n", 
     progname);
  exit(-1);
}

volatile int exiting = 0;

void signal_handler(int signo)
{
  switch (signo) {
  case SIGUSR1:
    if (pbc)
      pbc->list_binding();
    load_sadb();
    break;

  default:
    syslog(LOG_INFO, "received signal no: %d, stopping %s daemon", signo, progname);
    closelog();
    exiting = 1;
  }
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
    daemonize(progname, signal_handler);
    signal(SIGUSR1, signal_handler);
    openlog(progname, 0, LOG_DAEMON);

    in_iface homeif(ifname);
    syslog(LOG_INFO, "start %s daemon on HA address %s", progname, homeif.addr().to_string());

    ha_socket hagent(homeif);
    ha_bcache bc(homeif);
    pbc = &bc;

    while(!exiting) {
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
    syslog(LOG_WARNING, "%s", e.what());
    return -1;
  }

  return 0;
}

