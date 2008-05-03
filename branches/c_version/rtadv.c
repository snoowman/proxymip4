#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <asm/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/ip_icmp.h>

#include "common.h"
#include "rfc1256.h"
#include "rfc3344.h"

char *progname;

int MaxAdvertisementInterval = DEFAULT_MAX_ADVERTISEMENT_INTERVAL;
int MinAdvertisementInterval = 0;
int AdvertisementLifetime    = 0;

static int create_rtadv_msg(void* buf, int size, in_addr_t addr, int prefix);
static void set_seq(void* buf, int size, __u16 seq);
static void send_rtadv(int sock_icmp, char* ifname, int broadcast);
static void recv_rtsol(int sock_icmp, char* buf, int len, int delay_us);

static void usage()
{
	fprintf(stderr, "\
Usage: %s -i <interface> [-b] [-m num] [-n num] [-l num]\n\
  -i   send router advertisement to interface\n\
  -b   sent router advertisement to 255.255.255.255 instead of 224.0.0.1\n\
  -m   set MaxAdvertisementInterval, default %d\n\
  -n   set MinAdvertisementInterval, default 0.75 * MaxAdvertisementInterval\n\
  -l   set AdvertisementLifetime, default 3 * MaxAdvertisementInterval\n", 
 		progname, MaxAdvertisementInterval);
	exit(-1);
}

int main(int argc, char** argv)
{
	char *p, c, unused;
	char *ifname = NULL;
	int broadcast = 0;

	progname = argv[0];
	if ((p = strrchr(progname, '/')) != NULL)
		progname = p + 1;

	while ((c = getopt(argc, argv, "i:m:n:l:b")) != -1) {
		switch (c) {
		case 'i':
			ifname = optarg;
			break;
		case 'b':
			broadcast = 1;
			break;
		case 'm':
			if (sscanf(optarg, "%d%c", &MaxAdvertisementInterval, &unused) != 1) {
				fprintf(stderr, "bad value %s\n", optarg);
				usage();
			}
			break;
		case 'n':
			if (sscanf(optarg, "%d%c", &MinAdvertisementInterval, &unused) != 1) {
				fprintf(stderr, "bad value %s\n", optarg);
				usage();
			}
			break;
		case 'l':
			if (sscanf(optarg, "%d%c", &AdvertisementLifetime, &unused) != 1) {
				fprintf(stderr, "bad value %s\n", optarg);
				usage();
			}
			break;
		default:
			usage();
		}
	}

	if (argc == 1)
		usage();
	
	if (ifname == NULL || strlen(ifname) == 0)
		usage();

	if (MinAdvertisementInterval == 0)
		MinAdvertisementInterval = DEFAULT_MIN_ADVERTISEMENT_INTERVAL(MaxAdvertisementInterval);
	
	if (AdvertisementLifetime == 0)
		AdvertisementLifetime = DEFAULT_ADVERTISEMENT_LIFETIME(MaxAdvertisementInterval);

	if (!IS_VALID_MAX_ADVERTISEMENT_INTERVAL(MaxAdvertisementInterval)) {
		fprintf(stderr, "invalid MaxAdvertisementInterval %d\n", MaxAdvertisementInterval);
		usage();
	}

	if (!IS_VALID_MIN_ADVERTISEMENT_INTERVAL(MinAdvertisementInterval, MaxAdvertisementInterval)) {
		fprintf(stderr, "invalid MinAdvertisementInterval %d\n", MinAdvertisementInterval);
		usage();
	}

	if (!IS_VALID_ADVERTISEMENT_LIFETIME(AdvertisementLifetime, MaxAdvertisementInterval)) {
		fprintf(stderr, "invalid AdvertisementLifetime %d\n", AdvertisementLifetime);
		usage();
	}

	printf("\
MaxAdvertisementInterval %d\n\
MinAdvertisementInterval %d\n\
AdvertisementLifetime %d\n", MaxAdvertisementInterval, MinAdvertisementInterval, AdvertisementLifetime);
	
	int sock_icmp;
	if ((sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
		perror("socket");
		exit(1);
	}

	send_rtadv(sock_icmp, ifname, broadcast);

	return 0;
}

int create_rtadv_msg(void *buf, ssize_t size, in_addr_t addr, int prefix)
{
	// NOTICE: does not verify size

	// len = ICMP header + 1 address + mipext + prefixext + padding;
	ssize_t rtadv_len = 8 + 8 + 8 + 3 + 1; 
	bzero(buf, rtadv_len);

	struct icmp *icmp = buf;
	icmp->icmp_type = ICMP_ROUTER_ADVERTISEMENT;
	icmp->icmp_code = 16;
	icmp->icmp_num_addrs = 1;
	icmp->icmp_wpa = 2;
	icmp->icmp_lifetime = htons(AdvertisementLifetime);

	struct icmp_ra_addr *ra_addr = buf + 8;
	ra_addr->ira_addr = addr;
	ra_addr->ira_preference = 0;

	struct ra_ext_hdr *ext = buf + 16; 
	ext->type = RA_MOBILITY_AGENT_EXTENTION_TYPE;
	ext->length = sizeof(struct ra_ext_magent_adv);

	struct ra_ext_magent_adv *madv = buf + 18; 
	madv->sequence = 0;
	madv->lifetime = 0xffff;
	madv->flag_H = 1;

	struct ra_ext_hdr *ext2 = buf + 24; 
	ext2->type = RA_PREFIX_LENGTHS_EXTENTION_TYPE;
	ext2->length = 1;
	
	__u8* pprefix = buf + 26;
	*pprefix = prefix;

	icmp->icmp_cksum = in_cksum(icmp, rtadv_len);

	return rtadv_len;
}

void set_seq(void *buf, ssize_t size, __u16 seq)
{
	// NOTICE: does not verify size
	ssize_t rtadv_len = 8 + 8 + 8 + 3 + 1; /* ICMP header + 1 address + mipext */;

	struct ra_ext_magent_adv *madv = buf + 18; 
	madv->sequence = htons(seq);

	struct icmp *icmp = buf;
	icmp->icmp_cksum = 0;
	icmp->icmp_cksum = in_cksum(icmp, rtadv_len);
}

void send_rtadv(int sock_icmp, char* ifname, int broadcast)
{
	// FIXME: no broadcast indeed
	struct sockaddr_in dest = {
		.sin_family = AF_INET,
		.sin_port = 0,
		.sin_addr.s_addr = htonl(INADDR_ALLHOSTS_GROUP),
	};

	sock_bind_if(sock_icmp, ifname);
	sock_set_icmpfilter(sock_icmp, ICMP_ROUTER_SOLICITATION); 
	sock_join_mcast(sock_icmp, INADDR_ALLRTRS_GROUP);

	in_addr_t addr = sock_get_if_addr(sock_icmp, ifname);
	int prefix = sock_get_if_prefix(sock_icmp, ifname);

	char buf[1500];
	int plen = create_rtadv_msg(buf, 1500, addr, prefix);

	int range_us = (MaxAdvertisementInterval - MinAdvertisementInterval) * 1000 * 1000;
	int base_us = MinAdvertisementInterval * 1000 * 1000;
	int init_us = MAX_INITIAL_ADVERT_INTERVAL * 1000 * 1000;

	randomize();

	int i = 0;
	for (;;) {
		if (i == 0x10000)
			i = 256;
		set_seq(buf, 1500, i);

		if (sendto(sock_icmp, buf, plen, 0, (struct sockaddr*) &dest, sizeof(dest)) == -1) { 
			perror("sentdto");
			exit(-1);
		}

		int us = base_us + rand() % range_us;
		if (i < MAX_INITIAL_ADVERTISEMENTS && us > init_us)
			us = init_us;

		printf("sending router advertisment (%d) after %d us delay\n", i + 1, us);
		recv_rtsol(sock_icmp, buf, plen, us);

		++i;
	}
}

void recv_rtsol(int sock_icmp, char *adv, int advlen, int delay_us)
{
	fd_set rfds;
	
	FD_ZERO(&rfds);
	FD_SET(sock_icmp, &rfds);
	
	struct timeval tv;
	tv.tv_sec  = delay_us / 1000000;
	tv.tv_usec = delay_us % 1000000;
	
	int retval;
	char buf[1500];

	while((retval = select(sock_icmp + 1, &rfds, NULL, NULL, &tv)) > 0) {
		struct sockaddr_in dest;
		socklen_t destlen = sizeof(dest);
		int plen = recvfrom(sock_icmp, buf, 1500, 0, 
			(struct sockaddr *)&dest, &destlen);

		struct icmp *p = (struct icmp*) (buf + sizeof(struct ip));
		plen -= sizeof(struct ip);
		if (in_cksum(p, plen) != 0)
			fprintf(stderr, "WARNING: wrong icmp checksum\n");

		if (p->icmp_type == ICMP_ROUTER_SOLICITATION) {
			printf("received router solicitation\n");
			if (sendto(sock_icmp, adv, advlen, 0, (struct sockaddr *)&dest, destlen) == -1)
				perror("WARNING: sendto");
		}
	}
	
	if (retval == -1) {
		perror("select()");
		exit(-1);
	}

	return;
}
