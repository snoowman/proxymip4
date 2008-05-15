#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "sockpp.hpp"
#include "posixpp.hpp"

#if 0
#include <sys/file.h>
#include <sys/time.h>
#include <sys/signal.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif


int send_pack(int s, in_addr src, struct sockaddr_ll *llsrc, struct sockaddr_ll *lldst)
{
  int err;
  unsigned char buf[256];
  bzero(buf, 256);

  struct arphdr *ah = (struct arphdr*)buf;
  unsigned char *p = (unsigned char *)(ah+1);

  ah->ar_hrd = htons(llsrc->sll_hatype);
  if (ah->ar_hrd == htons(ARPHRD_FDDI))
  	ah->ar_hrd = htons(ARPHRD_ETHER);
  ah->ar_pro = htons(ETH_P_IP);
  ah->ar_hln = 0;
  ah->ar_pln = 4;
  ah->ar_op  = htons(ARPOP_REPLY);

  memcpy(p, &src, 4);
  p+=4;

  in_addr dst;
  dst.s_addr = 0xffffffff;
  memcpy(p, &dst, 4);
  p+=4;

  err = sendto_ex(s, buf, p-buf, 0, (struct sockaddr*)lldst, sizeof(*lldst));
  return err;
}

void send_unarp(char *device, char *ip, int reply = 0)
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

  struct in_addr src;
  inet_aton_ex(ip, &src);

  struct sockaddr_ll llsrc;
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

  struct sockaddr_ll lldst = llsrc;
  memset(lldst.sll_addr, -1, lldst.sll_halen);

  send_pack(s, src, &llsrc, &lldst);
}

int main(int argc, char **argv)
{
  if (argc != 3) {
    printf("Usage: %s <ifname> ip\n", argv[0]);
    exit(-1);
  }

  send_unarp(argv[1], argv[2]);
}
