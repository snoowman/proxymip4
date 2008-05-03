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

cache *pbc = NULL;

static void usage()
{
  fprintf(stderr, "Usage: %s -i <iface>\n\
  -i   start mobile home agent on link 'iface'\n", 
     progname);
  exit(-1);
}

static void sigusr1(int signo)
{
  if (pbc)
    pbc->list_binding();
  load_sadb();
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
    printf("ha %s\n", homeif.addr().to_string());
    ha_socket hagent(homeif);

    cache bc(homeif);
    pbc = &bc;
    signal(SIGUSR1, sigusr1);

    for(;;) {
      struct mip_rrq q;
      in_address from;

      int errcode = hagent.recv(q, from);
      if (errcode == rfc3344::MIPCODE_ACCEPT) {
        if (q.lifetime == 0)
          bc.deregister_binding(q.hoa);
        else
          bc.register_binding(q.hoa, q.ha, q.coa, q.lifetime);
      }

      hagent.reply(errcode, q, from);
    }
  }
  catch(exception &e) {
    fprintf(stderr, "%s\n", e.what());
    return -1;
  }

  return 0;
}

