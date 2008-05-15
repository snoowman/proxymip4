#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "sockpp.hpp"
#include "rfc3344.hpp"

using namespace rfc3344;

#define PROC_NET_ARP "/proc/net/arp"

int load_homecn(in_addr_t *addrs, char const* homeif)
{
  std::ifstream arpf(PROC_NET_ARP);
  std::string line;

  // ignore first line
  std::getline(arpf, line);

  int count = 0;
  while (arpf && count != HOMECN_MAX) {
    std::getline(arpf, line);
    if (!line.length())
      break;

    std::stringstream ss(line);
    std::string ip, unused, iface;
    ss >> ip >> unused >> unused >> unused >> unused >> iface;

    if (iface == homeif) {
      sockpp::in_address addr(ip.c_str());
      addrs[count++] = addr.to_u32();
    }
  }
  return count;
}

int main(int argc, char **argv)
{
  if (argc != 2) {
    printf("Usage: %s <iface>\n", argv[0]);
    exit(-1);
  }
  in_addr_t addrs[HOMECN_MAX];
  int num = load_homecn(addrs, argv[1]);

  for (int i = 0; i != num; ++i) {
    printf("ip: %08x\n", addrs[i]);
  }
}

