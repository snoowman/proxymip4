#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <exception>
#include <boost/lexical_cast.hpp>
#include "rfc1256.hpp"
#include "rfc3344.hpp"
#include "sockpp.hpp"
#include "packet.hpp"

using namespace std;
using namespace boost;
using namespace rfc1256;
using namespace rfc3344;
using namespace sockpp;

char *progname;

static void usage()
{
  fprintf(stderr, "\
Usage: %s -i <interface> [-b] [-m num] [-n num] [-l num]\n\
  -i   send rtadv to interface\n\
  -m   set MaxAdvInterval, default %d\n\
  -n   set MinAdvInterval, default 0.75 * MaxAdvInterval\n\
  -l   set AdvLifetime, default 3 * MaxAdvInterval\n", 
     progname, MaxAdvInterval_Default);
  exit(-1);
}

void signal_handler(int signo)
{
  syslog(LOG_INFO, "stopped %s daemon on receiving signal no: %d", progname, signo);
  closelog();
  exit(-1);
}

int main(int argc, char** argv)
{
  progname = parse_progname(argv[0]);

  if (argc == 1)
    usage();

  router_vars router_vars;
  char *ifname = NULL;
  char c;

  try {
    while ((c = getopt(argc, argv, "i:m:n:l:")) != -1) {
      switch (c) {
      case 'i':
        ifname = optarg;
        break;
      case 'm':
        router_vars.max_adv(lexical_cast<int>(optarg));
        break;
      case 'n':
        router_vars.min_adv(lexical_cast<int>(optarg));
        break;
      case 'l':
        router_vars.adv_lifetime(lexical_cast<int>(optarg));
        break;
      default:
        usage();
      }
    }
  }
  catch(exception &e) {
    fprintf(stderr, "%s %s\n", e.what(), optarg);
    return -1;
  }

  if (ifname == NULL || strlen(ifname) == 0)
    usage();


  try {
    in_iface ifa(ifname);
    rtadv_socket rtadv(ifa, router_vars);

    volatile int signo;
    daemonize(progname, &signo);
    // overwrite default signal_handler
    signal(SIGTERM, signal_handler);

    syslog(LOG_INFO, "rf1256 variable MaxAdvInterval = %d", router_vars.max_adv());
    syslog(LOG_INFO, "rf1256 variable MinAdvInterval = %d", router_vars.min_adv());
    syslog(LOG_INFO, "rf1256 variable AdvLifetime    = %d", router_vars.adv_lifetime());

    rtadv.serv_multicast();
  }
  catch(exception &e) {
    fprintf(stderr, "%s\n", e.what());
    return -1;
  }

  return 0;
}
