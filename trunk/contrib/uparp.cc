#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "sockpp.hpp"
#include "posixpp.hpp"

int send_pack(int s, in_addr src, in_addr dst,
        struct sockaddr_ll *llsrc, struct sockaddr_ll *lldst, bool reply)
{
  int err;
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

  err = sendto_ex(s, buf, p-buf, 0, (struct sockaddr*)lldst, sizeof(*lldst));
  return err;
}

void update_arp(char *device, char *ip, char *mac, int reply = 0)
{
  sockpp::in_iface ifa(device);
  int ifindex = ifa.index();
  int ifflags = ifa.flags();

  if (!(ifflags & IFF_UP)) {
  	printf("Interface \"%s\" is down\n", device);
  	exit(-1);
  }
  if (ifflags & (IFF_NOARP|IFF_LOOPBACK)) {
  	printf("Interface \"%s\" is not ARPable\n", device);
  	exit(-1);
  }

  struct in_addr src, dst;
  inet_aton_ex(ip, &dst);
  src = dst;

  struct sockaddr_ll llsrc, lldst;
  llsrc.sll_family = AF_PACKET;
  llsrc.sll_ifindex = ifindex;
  llsrc.sll_protocol = htons(ETH_P_ARP);

  int s = socket_ex(PF_PACKET, SOCK_DGRAM, 0);
  bind_ex(s, (struct sockaddr*)&llsrc, sizeof(llsrc));

  socklen_t alen = sizeof(llsrc);
  getsockname_ex(s, (struct sockaddr*)&llsrc, &alen);

  if (llsrc.sll_halen == 0) {
  	printf("Interface \"%s\" is not ARPable (no ll address)\n", device);
  	exit(-1);
  }

  memcpy(llsrc.sll_addr, mac, llsrc.sll_halen);

  lldst = llsrc;
  memset(lldst.sll_addr, -1, lldst.sll_halen);
  send_pack(s, src, dst, &llsrc, &lldst, reply);
}

int main(int argc, char **argv)
{
  if (argc != 4) {
    printf("Usage: %s <ifname> ip mac\n", argv[0]);
    exit(-1);
  }

  update_arp(argv[1], argv[2], argv[3]);
}
