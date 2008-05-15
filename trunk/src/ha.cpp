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

