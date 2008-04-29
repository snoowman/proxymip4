#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include "common.h"
#include "rfc1256.h"

char *progname;

static void usage()
{
	fprintf(stderr, "\
Usage: %s -i <interface/source ip> [-b]\n\
  -i   send router solicitation to interface identified by name or IP addr\n\
  -b   sent router solicitation to 255.255.255.255 instead of 224.0.0.2\n",
 		progname);
	exit(-1);
}

static int create_rtsol_msg(char* buf, int size);
static void set_rtsol_source(int sock_icmp, char *iforip);
static void set_rtsol_dest(int sock_icmp, int broadcast, struct sockaddr_in *dest);
static void set_icmp_filter(int sock_icmp, int type);
static void send_rtsol(int sock_icmp, struct sockaddr_in *dest);
static int recv_rtadv(int sock_icmp);
static void sock_join_mcast(int sock_icmp, in_addr_t mcast);

int main(int argc, char** argv)
{
	char *p, c;
	char *iforip = NULL;
	int broadcast = 0;

	progname = argv[0];
	if ((p = strrchr(progname, '/')) != NULL)
		progname = p + 1;

	while ((c = getopt(argc, argv, "i:b")) != -1) {
		switch (c) {
		case 'i':
			iforip = optarg;
			break;
		case 'b':
			broadcast = 1;
			break;
		default:
			usage();
		}
	}

	if (argc == 1)
		usage();
	
	if (iforip == NULL || strlen(iforip) == 0)
		usage();
	
	int sock_icmp;
	if ((sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		perror("socket");
		exit(1);
	}

	set_rtsol_source(sock_icmp, iforip);

	struct sockaddr_in dest;
	set_rtsol_dest(sock_icmp, broadcast, &dest);

	set_icmp_filter(sock_icmp, ICMP_ROUTER_ADVERTISEMENT); 
	sock_join_mcast(sock_icmp, INADDR_ALLHOSTS_GROUP);

	send_rtsol(sock_icmp, &dest);

	return 0;
}

void set_rtsol_source(int sock_icmp, char *iforip)
{
	struct sockaddr_in source;
	source.sin_family = AF_INET;
	source.sin_port = 0;

	if (inet_aton(iforip, &source.sin_addr) == 0) {
		if (setsockopt(sock_icmp, SOL_SOCKET, SO_BINDTODEVICE, 
				iforip, strlen(iforip) + 1) == -1) {
			perror("setsockopt: SO_BINDTODEVICE");
			exit(-1);
		}
		struct ifreq ifr;
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, iforip, IFNAMSIZ-1);

		if (ioctl(sock_icmp, SIOCGIFINDEX, &ifr) < 0) {
			fprintf(stderr, "rtsol: unknown iface %s\n", iforip);
			exit(-1);
		}

		struct ip_mreqn imr;
		memset(&imr, 0, sizeof(imr));
		imr.imr_ifindex = ifr.ifr_ifindex;
		printf("if %d\n", (int)ifr.ifr_ifindex);
		if (setsockopt(sock_icmp, SOL_IP, IP_MULTICAST_IF, &imr, sizeof(imr)) == -1) {
			perror("setsockopt: IP_MULTICAST_IF");
			exit(-1);
		}
	}
	else {
		if (bind(sock_icmp, (struct sockaddr*)&source, sizeof(source))
				== -1) {
			perror("bind");
			exit(-1);
		}
	}


}

void set_rtsol_dest(int sock_icmp, int broadcast, struct sockaddr_in *dest)
{
	dest->sin_family = AF_INET;
	dest->sin_port = 0;

	if (broadcast)
		dest->sin_addr.s_addr = 0xffffffff; /* 255.255.255.255 */
	else
		dest->sin_addr.s_addr = htonl(INADDR_ALLRTRS_GROUP);

	if (setsockopt(sock_icmp, SOL_SOCKET, SO_BROADCAST, &broadcast,
			sizeof(broadcast)) < 0) {
		perror("setsockopt: SO_BROADCAST");
		exit(-1);
	}

	int pmtudisc = IP_PMTUDISC_DO;
	if (setsockopt(sock_icmp, SOL_IP, IP_MTU_DISCOVER, &pmtudisc,
			sizeof(pmtudisc)) == -1) {
		perror("setsockopt: IP_MTU_DISCOVER");
		exit(-1);
	}
}

int create_rtsol_msg(char *buf, ssize_t size)
{
	ssize_t rtsol_len = sizeof(struct icmphdr);
	if (size < rtsol_len)
		return -1;

	struct icmphdr icmp;
	bzero(&icmp, rtsol_len);
	icmp.type = ICMP_ROUTER_SOLICITATION;
	icmp.checksum = in_cksum(&icmp, rtsol_len);

	memcpy(buf, &icmp, rtsol_len);
	return rtsol_len;
}

void send_rtsol(int sock_icmp, struct sockaddr_in *dest)
{
	char buf[1500];
	int plen = create_rtsol_msg(buf, 1500);
	if (plen < 0) {
		fprintf(stderr, "cannot create router solicitation packet\n");
		exit(-1);
	}

	randomize();

	int i;
	for (i = 0; i < MAX_SOLICITATIONS; ++i) {
		int us = rand() %  (MAX_SOLICITATION_DELAY * 1000 * 1000);
		printf("sending router solicitation (%d) after %d us delay\n", i + 1, us);
		usleep(us);

		if (sendto(sock_icmp, buf, plen, 0, (struct sockaddr*)dest, sizeof(*dest)) == -1) { 
			perror("sentdto");
			exit(-1);
		}

		if (recv_rtadv(sock_icmp))
			break;
	}

	if (i == MAX_SOLICITATIONS) {
		printf("no router advertisement received. exit!\n");
		exit(-1);
	}
}

int recv_rtadv(int sock_icmp)
{
	fd_set rfds;
	
	FD_ZERO(&rfds);
	FD_SET(sock_icmp, &rfds);
	
	struct timeval tv;
	tv.tv_sec = SOLICITATION_INTERVAL;
	tv.tv_usec = 0;
	
	int retval;
	char buf[1500];

	while((retval = select(sock_icmp + 1, &rfds, NULL, NULL, &tv)) > 0) {
		int plen = recv(sock_icmp, buf, 1500, 0);
		struct icmp *p = (struct icmp*) (buf + sizeof(struct ip));
		plen -= sizeof(struct ip);

		if (p->icmp_type == ICMP_ROUTER_ADVERTISEMENT) {
			printf("received router advertisement\n");
			printf("    icmp len %d, cksum %hd, recksum %hd\n", 
				plen, p->icmp_cksum, in_cksum(p, plen));
			printf("    icmp type %hhd, code %hhd, naddr %hhd, wpa %hhd, life %hd\n", 
				p->icmp_type, p->icmp_code, 
				p->icmp_num_addrs, p->icmp_wpa, 
				ntohs(p->icmp_lifetime));

			int i;
			struct icmp_ra_addr *pa = &p->icmp_radv;
			for (i = 0; i < p->icmp_num_addrs; ++i) {
				struct in_addr tmp;
				tmp.s_addr = pa[i].ira_addr;
	
				printf("    router %d, address %s, preference %d\n", i,
					inet_ntoa(tmp), ntohs(pa[i].ira_preference));
			}

			break;
		}
	}
	
	if (retval == -1) {
		perror("select()");
		exit(-1);
	}
	else if (retval == 0) {
		printf("no router advertisement received in %d seconds.\n", SOLICITATION_INTERVAL); 
		return 0;
	}

	return 1;
}

void set_icmp_filter(int sock_icmp, int type)
{
	struct icmp_filter filt;

	filt.data = ~(1 << type);
	if (setsockopt(sock_icmp, SOL_RAW, ICMP_FILTER,
			(char*)&filt, sizeof(filt)) == -1) {
		perror("WARNING: setsockopt(ICMP_FILTER)");
	}
}

void sock_join_mcast(int sock_icmp, in_addr_t mcast)
{
	struct in_addr tmp;
	tmp.s_addr = mcast;
	if (!IN_MULTICAST(mcast)) {
		fprintf(stderr, "internal error: %s not a multicast IP address\n", inet_ntoa(tmp));
		exit(-1);
	}

	struct ip_mreq mreq;
	bzero(&mreq, sizeof(mreq));
	mreq.imr_multiaddr.s_addr = htonl(mcast);
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(sock_icmp, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
		perror("setsockopt: IP_ADD_MEMBERSHIP");
		exit(1);
	}
}

