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

int get_mac(char *mac, in_addr_t addr, char const* ifname)
{
  std::ifstream arpf(PROC_NET_ARP);
  std::string line;
  std::string straddr = sockpp::in_address(addr).to_string();

  // ignore first line
  std::getline(arpf, line);

  while (arpf) {
    std::getline(arpf, line);
    if (!line.length())
      break;

    std::stringstream ss(line);
    std::string ip, unused, strmac, iface;
    ss >> ip >> unused >> unused >> strmac >> unused >> iface;

    if (iface == ifname && straddr == ip) {
      sscanf(strmac.c_str(), "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX", 
        mac, mac + 1, mac + 2, mac + 3, mac + 4, mac + 5);
      return 1;
    }
  }
  return 0;
}

int main(int argc, char **argv)
{
  if (argc == 2) {
    in_addr_t addrs[HOMECN_MAX];
    int num = load_homecn(addrs, argv[1]);
  
    for (int i = 0; i != num; ++i) {
      printf("ip: %08x\n", addrs[i]);
    }
  }
  else if (argc == 3) {
    in_addr_t addr = inet_addr(argv[1]);
    char mac[6];
    if (get_mac(mac, addr, argv[2])) {
      printf("%s: %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX\n", 
        argv[1], mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }
  }
  else {
    printf("Usage: %s <iface>\n", argv[0]);
    exit(-1);
  }
}

