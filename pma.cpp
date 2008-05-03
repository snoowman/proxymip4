#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <exception>
#include <boost/lexical_cast.hpp>
#include "common.hpp"
#include "rfc3344.hpp"
#include "sadb.hpp"
#include "sockpp.hpp"
//#include "network.h"

using namespace std;
using namespace boost;
using namespace rfc3344;

char *progname;

static void usage()
{
  fprintf(stderr, "Usage: %s -m <hoa> -c <coa> -h <ha> -s <spi> -i <if> -l <life>\n\
  -m   register home address 'hoa'\n\
  -c   using care-of address 'coa'\n\
  -h   register with home agent 'ha'\n\
  -l   lifetime, default to 0xfffe\n\
  -i   link 'if' which mn reside\n\
  -s   spi index for regstration\n",
     progname);
  exit(-1);
}


int main(int argc, char** argv)
{
  progname = parse_progname(argv[0]);

  char *hoa = NULL;
  char *ha = NULL;
  char *coa = NULL;
  char *ifname = NULL;
  __u32 spi = 0;
  __u16 lifetime = 0xfffe;

  try {
    char c;
    while ((c = getopt(argc, argv, "h:m:c:s:l:i:")) != -1) {
      switch (c) {
      case 'h':
        ha = optarg;
        break;
      case 'm':
        hoa = optarg;
        break;
      case 'c':
        coa = optarg;
        break;
      case 'i':
        ifname = optarg;
        break;
      case 'l':
        lifetime = lexical_cast<unsigned int>(optarg);
        break;
      case 's':
        spi =  lexical_cast<unsigned int>(optarg);
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
  
  if (ha == NULL || hoa == NULL || coa == NULL || ifname == NULL)
    usage();

  try {
    pma_socket pmagent;
    struct mip_rrp p = pmagent.request(ifname, hoa, ha, coa, spi, lifetime);
    fprintf(stderr, "reply code = %d, registration %s\n", p.code, 
        (p.code == MIPCODE_ACCEPT)? "successed":"failed");
  }
  catch (exception &e) {
    fprintf(stderr, "%s\n", e.what());
  }

#if 0
  char tif[IFNAMSIZ];
  tunnel_name(tif, IFNAMSIZ, p.ha);
  int tab = table_index(tif);

  // handle deregistration sucess
  if (lifetime == 0) {
    unregister_source_route(q.hoa, tab, ifname);
    set_proxy_arp(ifname, 0);
    unregister_route_to_tunnel(tif, tab);
    release_tunnel(tif);
  } 
  // handle registration success
  else {
    create_tunnel(tif, q.coa, p.ha);
    register_route_to_tunnel(tif, tab);
    set_proxy_arp(ifname, 1);
    register_source_route(q.hoa, tab, ifname);
  }
#endif
  return 0;
}
