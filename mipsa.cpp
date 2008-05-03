#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <exception>
#include <string>
#include <boost/lexical_cast.hpp>
#include "common.hpp"
#include "sadb.hpp"

using namespace std;
using namespace boost;
using namespace sadb;

char *progname;

static void usage()
{
  fprintf(stderr, "Usage: %s <command> [options]\n\
\n\
  available commands\n\
    add <spi> <secret> [-m|-s] [-t num|-n]\n\
                  add <spi> to sadb\n\
    del <spi>     delete entry <spi> from sadb\n\
    list [<spi>]  list entries in sadb\n\
    flush         flush sadb\n\
\n\
  available options\n\
    -m      using hmac-md5 for authentication\n\
    -s      using hmac-sha1 for authentication\n\
    -t num  using timestamp for replay protection\n\
            with 'num' seconds replay delay, default to 7\n\
    -n      using nonce for replay protection\n", 
     progname);
  exit(-1);
}

int main(int argc, char** argv)
{
  progname = parse_progname(argv[0]);

  char *hmac = "sha1";
  unsigned int replay = MIPSA_REPLAY_TIMESTAMP;
  unsigned int delay = 7;

  try {
    char c;
    while ((c = getopt(argc, argv, "msnt:")) != -1) {
      switch (c) {
      case 'm':
        hmac = "md5";
        break;
      case 's':
        hmac = "sha1";
        break;
      case 'n':
        replay = MIPSA_REPLAY_NONCE;
        delay = 0;
        break;
      case 't':
        replay = MIPSA_REPLAY_TIMESTAMP;
        if (optarg)
          delay = lexical_cast<unsigned int>(optarg);
        break;
      default:
        usage();
      }
    }
    string cmd = "list";
    if (argc > optind)
      cmd = argv[optind];
  
    __u32 spi = 0;
    if (argc > optind + 1)
      spi = lexical_cast<__u32>(argv[optind + 1]);
  
    load_sadb();
  
    if (cmd == "add") {
      if (argc < optind + 3)
        usage();

      char *secret = argv[optind + 2];
      add_sa(spi, secret, hmac, replay, delay);
    }
    else if (cmd == "del") {
      if (argc < optind + 2)
        usage();

      if (del_sa(spi))
        printf("%u removed from sadb\n", spi);
      else
        printf("%u not found in sadb\n", spi);
    }
    else if (cmd == "list") {
      list_sa(spi);
    }
    else if (cmd == "flush") {
      flush_sadb();
    }
    else {
      fprintf(stderr, "bad command %s\n", cmd.c_str());
      usage();
    }

    save_sadb();
  }
  catch (exception &e) {
    fprintf(stderr, "%s %s\n", e.what(), optarg);
    return -1;
  }

  return 0;
}
