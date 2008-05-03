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
//#include "bcache.h"

using namespace std;
using namespace sockpp;
using namespace rfc3344;
using namespace sadb;

char *progname;

static void usage()
{
  fprintf(stderr, "Usage: %s -i <iface>\n\
  -i   start mobile home agent on link 'iface'\n", 
     progname);
  exit(-1);
}

static void sigusr1(int signo)
{
  //list_binding();
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

  if (argc == 1)
    usage();
  
  if (ifname == NULL || strlen(ifname) == 0)
    usage();
  
  try {
    signal(SIGUSR1, sigusr1);

    in_iface homeif(ifname);
    printf("ha %s\n", homeif.addr().to_string());
    ha_socket hagent(homeif);
  
    for(;;) {
      struct mip_rrq q;
      in_address from;
      int errcode = hagent.recv(q, from);
      // proccess rrq
      // ...
      hagent.reply(errcode, q, from);
    }
  }
  catch(exception &e) {
    fprintf(stderr, "%s\n", e.what());
    return -1;
  }

  return 0;
}

