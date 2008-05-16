#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <fstream>
#include <sstream>

#include "network.hpp"
#include "posixpp.hpp"
#include "sockpp.hpp"

int my_system(char const *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char cmd[1024];
	vsnprintf(cmd, 1000, fmt, ap);
	va_end(ap);

	syslog(LOG_DEBUG, "executing \"%s\"", cmd);
	int ret =  system(cmd);
	if (ret != 0)
		syslog(LOG_WARNING, "previous command exited with code %d", ret);
	return ret;
}

char *tunnel_name(in_addr_t raddr)
{
	static char buf[IFNAMSIZ];
	snprintf(buf, IFNAMSIZ - 1, "mit%08x", raddr);
	return buf;
}

int create_tunnel(in_addr_t laddr, in_addr_t raddr)
{
	struct in_addr addr;

	addr.s_addr = laddr;
	char local[20];
	snprintf(local, 20, "%s", inet_ntoa(addr));

	addr.s_addr = raddr;
	char remote[20];
	snprintf(remote, 20, "%s", inet_ntoa(addr));

	my_system("ip tunnel add %s mode ipip remote %s local %s", tunnel_name(raddr), remote, local);
	my_system("ifconfig %s 0.0.0.0 up", tunnel_name(raddr));
	return 0;
}

int release_tunnel(in_addr_t raddr)
{
	my_system("ip tunnel del %s", tunnel_name(raddr));
	return 0;
}

int register_hoa(in_addr_t hoa, char const *hif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

        my_system("arp -n -Ds %s %s pub", mnaddr, hif);
	return 0;
}

int deregister_hoa(in_addr_t hoa, char const *hif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	my_system("arp -n -d %s -i %s pub", mnaddr, hif);
	return 0;
}	

int register_hoa_route(in_addr_t hoa, in_addr_t coa, char const *hif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	my_system("ip route add %s/32 dev %s", mnaddr, tunnel_name(coa));
	return 0;
}

int deregister_hoa_route(in_addr_t hoa, in_addr_t coa, char const *hif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	my_system("ip route del %s/32 dev %s", mnaddr, tunnel_name(coa));
	return 0;
}	

int set_proxy_arp(char const *mif, int flag)
{
	char proc[1024];

	snprintf(proc, 1024, "/proc/sys/net/ipv4/conf/%s/proxy_arp", mif);

	FILE *fp = fopen(proc, "w");
	if (fp == NULL)
		return -1;
	
	int c = (flag)? '1':'0';
	fputc(c, fp);
	fclose(fp);

	return 0;
}

int register_route_to_tunnel(in_addr_t ha, int tab)
{
	my_system("ip route add default dev %s table %d", tunnel_name(ha), tab);
	return 0;
}

int unregister_route_to_tunnel(in_addr_t ha, int tab)
{
	my_system("ip route del default dev %s table %d", tunnel_name(ha), tab);
	return 0;
}

int register_source_route(in_addr_t hoa, int tab, char const *mif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	my_system("ip route add %s/32 dev %s", mnaddr, mif);
	my_system("ip rule add from %s/32 lookup %d", mnaddr, tab);
	return 0;
}

int unregister_source_route(in_addr_t hoa, int tab, char const *mif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	my_system("ip route del %s/32 dev %s", mnaddr, mif);
	my_system("ip rule del from %s/32 lookup %d", mnaddr, tab);
	return 0;
}

void send_arp(int s, in_addr_t src, in_addr_t dst,
        struct sockaddr_ll *llsrc, struct sockaddr_ll *lldst, bool reply = false)
{
  unsigned char buf[256];
  struct arphdr *ah = (struct arphdr*)buf;
  unsigned char *p = (unsigned char *)(ah+1);

  ah->ar_hrd = htons(llsrc->sll_hatype);
  if (ah->ar_hrd == htons(ARPHRD_FDDI))
    ah->ar_hrd = htons(ARPHRD_ETHER);
  ah->ar_pro = htons(ETH_P_IP);
  ah->ar_hln = llsrc->sll_halen;
  ah->ar_pln = 4;

  short op = reply ? htons(ARPOP_REPLY) : htons(ARPOP_REQUEST);
  ah->ar_op  = op;

  memcpy(p, &llsrc->sll_addr, ah->ar_hln);
  p+=llsrc->sll_halen;

  memcpy(p, &src, 4);
  p+=4;

  if (reply)
    memcpy(p, &llsrc->sll_addr, ah->ar_hln);
  else
    memcpy(p, &lldst->sll_addr, ah->ar_hln);
  p+=ah->ar_hln;

  memcpy(p, &dst, 4);
  p+=4;

  sendto_ex(s, buf, p-buf, 0, (struct sockaddr*)lldst, sizeof(*lldst));
}

void send_grat_arp(char const *device, in_addr_t *addr, int num_addr, bool use_local)
{
  sockpp::in_iface ifa(device);
  int ifindex = ifa.index();
  int ifflags = ifa.flags();

  if (!(ifflags & IFF_UP)) {
    syslog(LOG_WARNING, "Interface \"%s\" is down", device);
    syslog(LOG_WARNING, "failed sending gratuitous ARP");
    return;
  }
  if (ifflags & (IFF_NOARP|IFF_LOOPBACK)) {
    syslog(LOG_WARNING, "Interface \"%s\" is not ARPable", device);
    syslog(LOG_WARNING, "failed sending gratuitous ARP");
    return;
  }

  struct sockaddr_ll llsrc, lldst;
  llsrc.sll_family = AF_PACKET;
  llsrc.sll_ifindex = ifindex;
  llsrc.sll_protocol = htons(ETH_P_ARP);

  int s = socket_ex(PF_PACKET, SOCK_DGRAM, 0);
  bind_ex(s, (struct sockaddr*)&llsrc, sizeof(llsrc));

  socklen_t alen = sizeof(llsrc);
  getsockname_ex(s, (struct sockaddr*)&llsrc, &alen);

  if (llsrc.sll_halen == 0) {
    syslog(LOG_WARNING, "Interface \"%s\" is not ARPable (no ll address)", device);
    syslog(LOG_WARNING, "failed sending gratuitous ARP");
    return;
  }

  lldst = llsrc;
  memset(lldst.sll_addr, -1, lldst.sll_halen);

  for (int i = 0; i < 3; ++i) {
    usleep(50000);
    for (int j = 0; j < num_addr; ++j) {
      if (!use_local) {
        mac_addr mac;
        if (get_mac(&mac, addr[j], device))
	  memcpy(llsrc.sll_addr, &mac, llsrc.sll_halen);
      }

      send_arp(s, addr[j], addr[j], &llsrc, &lldst);
    }
  }
  close_ex(s);
}

void send_grat_arp2(char const *device, in_addr_t addr, mac_addr* mac)
{
  sockpp::in_iface ifa(device);
  int ifindex = ifa.index();
  int ifflags = ifa.flags();

  if (!(ifflags & IFF_UP)) {
    syslog(LOG_WARNING, "Interface \"%s\" is down", device);
    syslog(LOG_WARNING, "failed sending gratuitous ARP");
    return;
  }
  if (ifflags & (IFF_NOARP|IFF_LOOPBACK)) {
    syslog(LOG_WARNING, "Interface \"%s\" is not ARPable", device);
    syslog(LOG_WARNING, "failed sending gratuitous ARP");
    return;
  }

  struct sockaddr_ll llsrc, lldst;
  llsrc.sll_family = AF_PACKET;
  llsrc.sll_ifindex = ifindex;
  llsrc.sll_protocol = htons(ETH_P_ARP);

  int s = socket_ex(PF_PACKET, SOCK_DGRAM, 0);
  bind_ex(s, (struct sockaddr*)&llsrc, sizeof(llsrc));

  socklen_t alen = sizeof(llsrc);
  getsockname_ex(s, (struct sockaddr*)&llsrc, &alen);

  if (llsrc.sll_halen == 0) {
    syslog(LOG_WARNING, "Interface \"%s\" is not ARPable (no ll address)", device);
    syslog(LOG_WARNING, "failed sending gratuitous ARP");
    return;
  }

  memcpy(llsrc.sll_addr, mac, llsrc.sll_halen);
  lldst = llsrc;
  memset(lldst.sll_addr, -1, lldst.sll_halen);
  send_arp(s, addr, addr, &llsrc, &lldst);

  close_ex(s);
}

static char const *PROC_NET_ARP = "/proc/net/arp";

/*
 * load neighbor IP Addresses of an interface
 */
int load_neigh(in_addr_t *addrs, int max, char const* ifname, in_addr_t exclude)
{
  std::ifstream arpf(PROC_NET_ARP);
  std::string line;

  // ignore first line
  std::getline(arpf, line);

  int count = 0;
  while (arpf && count != max) {
    std::getline(arpf, line);
    if (!line.length())
      break;

    std::stringstream ss(line);
    std::string ip, unused, iface;
    ss >> ip >> unused >> unused >> unused >> unused >> iface;
    in_addr_t addr = sockpp::in_address(ip.c_str()).to_u32();

    if (iface == ifname && addr != exclude) {
      addrs[count++] = addr;
    }
  }
  return count;
}

/*
 * get MAC addresses of an neighbor
 */
int get_mac(mac_addr *mac, in_addr_t addr, char const* ifname)
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
      sscanf(strmac.c_str(), "%hhX:%hhX:%hhX:%hhX:%hhX:%hhX:", 
        mac->b, mac->b + 1, mac->b + 2, mac->b + 3, mac->b + 4, mac->b + 5);
      return 1;
    }
  }
  return 0;
}

