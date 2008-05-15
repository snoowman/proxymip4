#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
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

class rtadv_socket {
  sockpp::icmp_socket icmp_;
  sockpp::in_iface const &ifa_;
  rfc1256::router_vars &vars_;

private:
  int create_rtadv_msg(char *buf, ssize_t size)
  {
    ssize_t rtadv_len = 8 + 8 + 8 + 3 + 1;
    if (size < rtadv_len)
      throw packet::invalid_length();

    // len = ICMP header + 1 address + mipext + prefixext + padding;
    bzero(buf, rtadv_len);
  
    struct icmp *icmp = (struct icmp *)buf;
    icmp->icmp_type = rfc1256::ICMP_ROUTER_ADV;
    icmp->icmp_code = 16;
    icmp->icmp_num_addrs = 1;
    icmp->icmp_wpa = 2;
    icmp->icmp_lifetime = htons(vars_.adv_lifetime());
  
    struct icmp_ra_addr *ra_addr = (struct icmp_ra_addr *)(buf + 8);
    ra_addr->ira_addr = ifa_.addr().to_u32();
    ra_addr->ira_preference = 0;
  
    raext_hdr *ext = (raext_hdr *)(buf + 16);
    ext->type = RAEXT_MOBIAGENT;
    ext->length = sizeof(raext_madv);
  
    raext_madv *madv = (raext_madv *)(buf + 18);
    madv->sequence = htons(vars_.increase_seq());
    madv->lifetime = 0xffff;
    madv->flag_H = 1;
  
    raext_hdr *ext2 = (raext_hdr *)(buf + 24);
    ext2->type = RAEXT_PREFLEN;
    ext2->length = 1;
  
    __u16 *ppreflen = (__u16 *)(buf + 26);
    *ppreflen = ifa_.preflen();
  
    icmp->icmp_cksum = packet::in_cksum(icmp, rtadv_len);
  
    return rtadv_len;
  }

public:
  rtadv_socket(sockpp::in_iface const &ifa, rfc1256::router_vars &vars)
    : ifa_(ifa), vars_(vars)
  {
    icmp_.bindif(ifa); 
    icmp_.join_mcast(sockpp::in_address(htonl(INADDR_ALLRTRS_GROUP)));
    icmp_.icmp_filter(rfc1256::ICMP_ROUTER_SOL);
  }
  
  void send_rtadv(sockpp::in_address dest) {
    char buf[packet::MTU];  
    int len = create_rtadv_msg(buf, packet::MTU);
    icmp_.sendto(buf, len, dest);
  }

  sockpp::in_address recv_rtsol() {
    char buf[packet::MTU];

    sockpp::in_address ret;
    int len = icmp_.recvfrom(buf, packet::MTU, ret);
    
    struct icmp *p = (struct icmp*) (buf + sizeof(struct ip));
    len -= sizeof(struct ip);
    if (packet::in_cksum(p, len) != 0)
      throw packet::bad_packet("bad icmp cksum");
  
    if (p->icmp_type != rfc1256::ICMP_ROUTER_SOL)
      throw packet::bad_packet("unexpected icmp type");

    return ret;
  }

  void serv_multicast() {
    sockpp::in_address multicast(htonl(INADDR_ALLHOSTS_GROUP));

    try {
      for (;;) {
        send_rtadv(multicast);
  
        timeval tv = vars_.adv_interval();
        syslog(LOG_INFO, "sending rtadv after %lu.%06lu s delay\n", tv.tv_sec, tv.tv_usec);
        reply_unicast_timeout(tv);
      }
    }
    catch (std::exception &e) {
      syslog(LOG_ERR, "error: %s", e.what());
    }
  }

  void reply_unicast_timeout(timeval &tv) {
    while(icmp_.select_read(tv) > 0) {
      try {
        sockpp::in_address sol_addr = recv_rtsol();
        send_rtadv(sol_addr);
      }
      catch (packet::bad_packet &e) {
        syslog(LOG_WARNING, "%s\n", e.what());
      }
    }
  }
};

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
