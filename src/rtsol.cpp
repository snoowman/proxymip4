#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <exception>
#include "common.hpp"
#include "sockpp.hpp"
#include "packet.hpp"
#include "rfc3344.hpp"

using namespace packet;
using namespace rfc3344;
using namespace sockpp;

char *progname;

static void usage()
{
  fprintf(stderr, "\
Usage: %s -i <interface> [-b]\n\
  -i   send router solicitation to interface\n\
  -d   do not bind to interface\n",
     progname);
  exit(-1);
}

int main(int argc, char** argv)
{
  progname = parse_progname(argv[0]);

  if (argc == 1)
    usage();

  char *ifname = NULL;
  int dontbind = 0;
  char c;

  try {
    while ((c = getopt(argc, argv, "i:d")) != -1) {
      switch (c) {
      case 'i':
        ifname = optarg;
        break;
      case 'd':
        dontbind = 1;
        break;
      default:
        usage();
      }
    }
  }
  catch (std::exception &e) {
    fprintf(stderr, "%s %s\n", e.what(), optarg);
    return -1;
  }
  
  if (ifname == NULL || strlen(ifname) == 0)
    usage();

  try {
    in_iface ifa(ifname);
    rtsol_socket rtsol;

    if (!dontbind)
      rtsol.bindif(ifa);

    rtsol.solicit();
  }
  catch (std::exception &e) {
    fprintf(stderr, "%s\n", e.what());
    return -1;
  }

  return 0;
}
