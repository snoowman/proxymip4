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
	fprintf(stderr, "Usage: %s -i <iface>\n\
  -i   start mobile home agent on link 'iface'\n", 
 		progname);
	exit(-1);
}

int verify_request(struct mip_reg_request *req, int plen, unsigned long ha)
{
	int errcode = 0;
	if (req->type != MIP_REQUEST_TYPE) {
		fprintf(stderr, "incorrect MIP type value %d\n", req->type);
		errcode = MIPE_BAD_FORMAT;
	}

	if (plen != MIP_MSG_SIZE2(*req)) {
		fprintf(stderr, "incorrect packet length %d\n", plen);
		errcode = MIPE_BAD_FORMAT;
	}

	if (req->ha != ha) {
		fprintf(stderr, "incorrect home agent address %08lx\n", req->ha);
		errcode = MIPE_BAD_HA;
		return 0;
	}

	int authlen = authlen_by_spi(req);
	if (authlen != req->auth.length) {
		fprintf(stderr, "incorrect auth length %d", authlen);
		errcode = MIPE_BAD_FORMAT;
	}

	char auth[MIP_AUTH_MAX];
	auth_by_spi(auth, req);
	if (memcmp(auth, req->auth.auth, authlen) != 0) {
		fprintf(stderr, "mobile node faild authentication\n");
		errcode = MIPE_BAD_AUTH;
	}
	
	// TODO: check hoa, id
	return errcode;
}

void create_reg_reply(struct mip_reg_reply *rep, struct mip_reg_request *req, int errcode)
{
	bzero(rep, sizeof(*rep));
	rep->type = MIP_REPLY_TYPE;
	rep->code = errcode;
	rep->lifetime = req->lifetime;
	rep->hoa = req->hoa;
	rep->ha = req->ha;
	rep->id = req->id;

	rep->auth.type = MIPEXT_AUTH_TYPE;
	rep->auth.spi = htonl(1);
}

int main(int argc, char** argv)
{
	char *p, c;
	char *ifname = NULL;

	progname = argv[0];
	if ((p = strrchr(progname, '/')) != NULL)
		progname = p + 1;

	while ((c = getopt(argc, argv, "i:")) != -1) {
		switch (c) {
		case 'i':
			ifname = optarg;
			break;
		default:
			usage();
		}
	}

	if (argc == 1)
		usage();
	
	if (ifname == NULL || strlen(ifname) == 0)
		usage();
	
	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("socket");
		exit(-1);
	}

	struct sockaddr_in sa_ha;
	sa_ha.sin_family = AF_INET;
	sa_ha.sin_port = htons(MIP_UDP_PORT);
	sa_ha.sin_addr.s_addr = INADDR_ANY;
	if (bind(sock, (struct sockaddr *)&sa_ha, sizeof(sa_ha)) == -1) {
		perror("bind");
		exit(-1);
	}

	unsigned long ha = sock_get_if_addr(sock, ifname);
	printf("ha %08lx\n", ha);

	for(;;) {
		struct mip_reg_request req;
		struct sockaddr_in sa_mn;
		socklen_t sa_len = sizeof(sa_mn);
		int plen = recvfrom(sock, &req, sizeof(req), 0, (struct sockaddr*)&sa_mn, &sa_len);
		if (plen == -1) {
			perror("recvfrom");
			exit(-1);
		}

		int errcode =  verify_request(&req, plen, ha);
		struct mip_reg_reply rep;
		create_reg_reply(&rep, &req, errcode);

		if (sendto(sock, &rep, MIP_MSG_SIZE2(rep), 0, (struct sockaddr*)&sa_mn, sa_len) == -1) {
			perror("sendto");
			exit(-1);
		}
	}

	return 0;
}
