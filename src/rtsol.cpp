#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <exception>
#include "common.hpp"
#include "sockpp.hpp"
#include "packet.hpp"
#include "rfc1256.hpp"
#include "rfc3344.hpp"

using namespace packet;
using namespace rfc3344;
using namespace rfc1256;
using namespace sockpp;

class rtsol_socket {
  sockpp::icmp_socket icmp_;

private:
  int create_rtsol_msg(void* buf, ssize_t size) {
    ssize_t rtsol_len = 8 /* ICMP header */;
    if (size < rtsol_len)
      throw packet::invalid_length();
  
    bzero(buf, rtsol_len);
  
    struct icmphdr *icmp = (struct icmphdr *)buf;
    icmp->type = rfc1256::ICMP_ROUTER_SOL;
    icmp->checksum = packet::in_cksum(icmp, rtsol_len);
  
    return rtsol_len;
  }

public:
  rtsol_socket() {
    icmp_.join_mcast(sockpp::in_address(htonl(INADDR_ALLHOSTS_GROUP)));
    icmp_.icmp_filter(rfc1256::ICMP_ROUTER_ADV);
  }

  void bindif(sockpp::in_iface const &ifa) {
    icmp_.bindif(ifa);
  }

  void send_rtsol() {
    char buf[packet::MTU];
    int len = create_rtsol_msg(buf, packet::MTU);

    sockpp::in_address dest(htonl(INADDR_ALLRTRS_GROUP));
    icmp_.sendto(buf, len, dest);
  }

  void delay() {
      int sec = rand() % rfc1256::MaxSolDelay;
      int usec = rand() % 1000000;
      printf("sending rtsol with %d.%06d s delay\n", sec, usec);
      sleep(sec);
      usleep(usec);
  }

  void solicit() {
    randomize();

    int i;
    for (i = 0; i < rfc1256::MaxSolNum; ++i) {
      delay();
      send_rtsol();
  
      if (recv_rtadv())
        break;
    }
  
    if (i == rfc1256::MaxSolNum) {
      printf("no router advertisement received. exit!\n");
      exit(-1);
    }
  }

  bool recv_rtadv()
  {
    struct timeval tv;
    tv.tv_sec = rfc1256::SolInterval;
    tv.tv_usec = 0;

    char buf[packet::MTU];
    if(icmp_.select_read(tv)) {
      int len = icmp_.recv(buf, packet::MTU);
      print_rtadv(buf, len);
      return true;
    }

    printf("no rtadv received in %d seconds\n", rfc1256::SolInterval); 
    return false;
  }

  void print_rtadv(char *buf, int len)
  {
    struct icmp *p = (struct icmp*) (buf + sizeof(struct ip));
    len -= sizeof(struct ip);
  
    if (p->icmp_type == rfc1256::ICMP_ROUTER_ADV) {
      printf("received router advertisement\n");
      printf("    icmp len %d, cksum %hu, recksum %hu\n", 
        len, p->icmp_cksum, packet::in_cksum(p, len));
      printf("    icmp type %hhu, code %hhu, naddr %hhu, wpa %hhu, life %hu\n", 
        p->icmp_type, p->icmp_code, 
        p->icmp_num_addrs, p->icmp_wpa, 
        ntohs(p->icmp_lifetime));
  
      int i;
      struct icmp_ra_addr *pa = &p->icmp_radv;
      if (len > 8 + p->icmp_num_addrs * p->icmp_wpa * 4) {
        ra_ext_hdr *ext = (ra_ext_hdr *)(buf + 28 + p->icmp_num_addrs * p->icmp_wpa * 4);
        if (ext->type == RA_EXTTYPE_MOBIAGENT) {
          printf("mobile agent advertisement extension\n");
          ra_ext_magent_adv *madv = (ra_ext_magent_adv *)((char *)ext + sizeof(*ext));
          printf("    seq %hu, lifetime %hu, flags %hhu\n", 
            ntohs(madv->sequence), ntohs(madv->lifetime), madv->flags);
        }
        ra_ext_hdr *ext2 = (ra_ext_hdr *)((char *)ext + sizeof(*ext) + ext->length);
        if (ext2->type == RA_EXTTYPE_PREFLEN) {
          __u8 *prefix = (__u8 *)((char *)ext2 + 2);
          for (i = 0; i < p->icmp_num_addrs; ++i) {
            in_addr tmp;
            tmp.s_addr = pa[i].ira_addr;
  
            printf("    home agent %d, address %s, preference %hu, prefix %hhu\n", i,
              inet_ntoa(tmp), ntohs(pa[i].ira_preference), prefix[i]);
          }
        }
      }
      else {
        for (i = 0; i < p->icmp_num_addrs; ++i) {
          struct in_addr tmp;
          tmp.s_addr = pa[i].ira_addr;
  
          printf("    router %d, address %s, preference %hu\n", i,
            inet_ntoa(tmp), ntohs(pa[i].ira_preference));
        }
      }
    }
  }
};

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
