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
#include "bcache.hpp"

using namespace std;
using namespace boost;
using namespace rfc3344;
using namespace bcache;
using namespace sockpp;

char *progname;

static void usage()
{
  fprintf(stderr, "Usage: %s -m <hoa> -c <coa> -h <ha> -s <spi> -i <if> -l <life> -f\n\
  -m   register home address 'strhoa'\n\
  -f   force free resource local\n\
  -c   using care-of address 'strcoa'\n\
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

  in_addr_t hoa = 0;
  in_addr_t ha = 0;
  in_addr_t coa = 0;
  char *ifname = NULL;
  __u32 spi = 0;
  __u16 lifetime = 0xfffe;
  bool force = false;

  try {
    char c;
    while ((c = getopt(argc, argv, "h:m:c:s:l:i:f")) != -1) {
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
      case 'f':
        force = true;
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
  
  if (ha == 0 || hoa == 0 || coa == 0 || ifname == NULL)
    usage();

  try {
    pma_socket pmagent;
    pma_bcache bc;

    struct mip_rrp p = pmagent.request(hoa, ha, coa, spi, lifetime);
    if (p.code != MIPCODE_ACCEPT) {
      fprintf(stderr, "reply code = %d, registration failed\n", p.code);
      return -1;
    }

    bc.register_mif(hoa, ifname);
    if (lifetime == 0) {
      if (force)
        bc.deregister_local(hoa, ha, coa);
      else
        bc.deregister_binding(hoa);
    }
    else {
      bc.register_binding(hoa, ha, coa, spi, lifetime);
    }
  }
  catch (exception &e) {
    fprintf(stderr, "%s\n", e.what());
  }

  return 0;
}
