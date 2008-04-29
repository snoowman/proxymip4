#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>

#include "common.h"
#include "rfc1256.h"
#include "rfc3344.h"

char *progname;

static void usage()
{
	fprintf(stderr, "\
Usage: %s -i <interface> [-b]\n\
  -i   send router solicitation to interface\n\
  -b   sent router solicitation to 255.255.255.255 instead of 224.0.0.2\n\
  -d   do not bind to interface\n",
 		progname);
	exit(-1);
}

static int create_rtsol_msg(void *buf, int size);
static void send_rtsol(int sock_icmp, int broadcast);
static int recv_rtadv(int sock_icmp);
static void parse_rtadv(void *buf, int len);

int main(int argc, char** argv)
{
	char *p, c;
	char *ifname = NULL;
	int broadcast = 0;
	int dontbind = 0;

	progname = argv[0];
	if ((p = strrchr(progname, '/')) != NULL)
		progname = p + 1;

	while ((c = getopt(argc, argv, "i:db")) != -1) {
		switch (c) {
		case 'i':
			ifname = optarg;
			break;
		case 'b':
			broadcast = 1;
			break;
		case 'd':
			dontbind = 1;
			break;
		default:
			usage();
		}
	}

	if (argc == 1)
		usage();
	
	if (ifname == NULL || strlen(ifname) == 0)
		usage();
	
	int sock_icmp;
	if ((sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		perror("socket");
		exit(1);
	}

	if (!dontbind)
		sock_bind_if(sock_icmp, ifname);

	sock_set_icmpfilter(sock_icmp, ICMP_ROUTER_ADVERTISEMENT); 
	sock_join_mcast(sock_icmp, INADDR_ALLHOSTS_GROUP);

	send_rtsol(sock_icmp, broadcast);

	return 0;
}

int create_rtsol_msg(void* buf, ssize_t size)
{
	ssize_t rtsol_len = 8 /* ICMP header */;
	if (size < rtsol_len) {
		fprintf(stderr, "cannot create router advertisement packet\n");
		exit(-1);
	}
	bzero(buf, rtsol_len);

	struct icmphdr *icmp = buf;
	icmp->type = ICMP_ROUTER_SOLICITATION;
	icmp->checksum = in_cksum(icmp, rtsol_len);

	return rtsol_len;
}

void send_rtsol(int sock_icmp, int broadcast)
{
	// FIXME: no broadcast indeed
	struct sockaddr_in dest = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr.s_addr = htonl(INADDR_ALLRTRS_GROUP),
	};

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

		if (sendto(sock_icmp, buf, plen, 0, (struct sockaddr*) &dest, sizeof(dest)) == -1) { 
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

	if((retval = select(sock_icmp + 1, &rfds, NULL, NULL, &tv)) > 0) {
		int plen = recv(sock_icmp, buf, 1500, 0);
		if (plen == -1) {
			perror("recv");
			exit(-1);
		}

		parse_rtadv(buf, plen);
	}
	else if (retval == -1) {
		perror("select()");
		exit(-1);
	}
	else if (retval == 0) {
		printf("no router advertisement received in %d seconds.\n", SOLICITATION_INTERVAL); 
		return 0;
	}

	return 1;
}

void parse_rtadv(void *buf, int len)
{
	// TODO: should check validity
	struct icmp *p = (struct icmp*) (buf + sizeof(struct ip));
	len -= sizeof(struct ip);

	if (p->icmp_type == ICMP_ROUTER_ADVERTISEMENT) {
		printf("received router advertisement\n");
		printf("    icmp len %d, cksum %hu, recksum %hu\n", 
			len, p->icmp_cksum, in_cksum(p, len));
		printf("    icmp type %hhu, code %hhu, naddr %hhu, wpa %hhu, life %hu\n", 
			p->icmp_type, p->icmp_code, 
			p->icmp_num_addrs, p->icmp_wpa, 
			ntohs(p->icmp_lifetime));

		int i;
		struct icmp_ra_addr *pa = &p->icmp_radv;
		if (len > 8 + p->icmp_num_addrs * p->icmp_wpa * 4) {
			struct ra_ext_hdr *ext = buf + 28 + p->icmp_num_addrs * p->icmp_wpa * 4;
			if (ext->type == RA_MOBILITY_AGENT_EXTENTION_TYPE) {
				printf("mobile agent advertisement extension\n");
				struct ra_ext_magent_adv *madv = (void*)ext + sizeof(*ext);
				printf("    seq %hu, lifetime %hu, flags %hhu\n", 
					ntohs(madv->sequence), ntohs(madv->lifetime), madv->flags);
			}
			struct ra_ext_hdr *ext2 = (void*) ext + sizeof(*ext) + ext->length;
			if (ext2->type == RA_PREFIX_LENGTHS_EXTENTION_TYPE) {
				unsigned char *prefix = (void*) ext2 + 2;
				for (i = 0; i < p->icmp_num_addrs; ++i) {
					struct in_addr tmp;
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
