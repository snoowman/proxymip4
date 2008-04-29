#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#include "common.h"
#include "rfc1256.h"
#include "rfc3344.h"

char *progname;

static void usage()
{
	fprintf(stderr, "Usage: %s -a <hoa> -c <coa> -m <ha>\n\
  -a   register home address 'hoa'\n\
  -c   using care-of address 'coa'\n\
  -m   register with home agent 'ha'\n", 
 		progname);
	exit(-1);
}

void create_reg_request(struct mip_reg_request *req, in_addr_t hoa, in_addr_t ha, in_addr_t coa)
{
	bzero(req, sizeof(*req));
	req->type = MIP_REQUEST_TYPE;
	req->flag_D = 1;
	req->flag_T = 1;
	req->lifetime = htons(0xfffe);

	req->hoa = hoa;
	req->ha = ha;
	req->coa = coa;

	req->auth.type = MIPEXT_AUTH_TYPE;
	req->auth.spi = htonl(1);
}

int main(int argc, char** argv)
{
	char *p, c;
	char *hoa = NULL;
	char *ha = NULL;
	char *coa = NULL;

	progname = argv[0];
	if ((p = strrchr(progname, '/')) != NULL)
		progname = p + 1;

	while ((c = getopt(argc, argv, "a:m:c:")) != -1) {
		switch (c) {
		case 'a':
			hoa = optarg;
			break;
		case 'm':
			ha = optarg;
			break;
		case 'c':
			coa = optarg;
			break;
		default:
			usage();
		}
	}

	if (argc == 1)
		usage();
	
	if (ha == NULL || strlen(ha) == 0)
		usage();

	if (hoa == NULL || strlen(hoa) == 0)
		usage();

	if (coa == NULL || strlen(coa) == 0)
		usage();

	int sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock == -1) {
		perror("socket");
		exit(-1);
	}

	struct sockaddr_in sa_coa;
	sa_coa.sin_family = AF_INET;
	sa_coa.sin_port = htons(0);
	if (inet_aton(coa, &sa_coa.sin_addr) == -1) {
		fprintf(stderr, "bad coa address %s\n", coa);
		exit(-1);
	}
	printf("coa: %08x\n", sa_coa.sin_addr.s_addr);

	if (bind(sock, (struct sockaddr *)&sa_coa, sizeof(sa_coa)) == -1) {
		perror("bind");
		exit(-1);
	}

	struct sockaddr_in sa_ha;
	sa_ha.sin_family = AF_INET;
	sa_ha.sin_port = htons(MIP_UDP_PORT);
	if (inet_aton(ha, &sa_ha.sin_addr) == -1) {
		fprintf(stderr, "bad ha address %s\n", ha);
		exit(-1);
	}
	printf("ha: %08x\n", sa_ha.sin_addr.s_addr);

	if (connect(sock, (struct sockaddr *)&sa_ha, sizeof(sa_ha)) == -1) {
		perror("connect");
		exit(-1);
	}

	struct sockaddr_in sa_hoa;
	sa_hoa.sin_family = AF_INET;
	if (inet_aton(hoa, &sa_hoa.sin_addr) == -1) {
		fprintf(stderr, "bad hoa address %s\n", hoa);
		exit(-1);
	}
	printf("hoa: %08x\n", sa_hoa.sin_addr.s_addr);

	struct mip_reg_request req;
	create_reg_request(&req, sa_hoa.sin_addr.s_addr, sa_ha.sin_addr.s_addr, sa_coa.sin_addr.s_addr);
	req.auth.length = authlen_by_spi(&req);
	auth_by_spi(req.auth.auth, &req);

	printf("size %d, size2 %d, size req %d\n", MIP_MSG_SIZE1(req), MIP_MSG_SIZE2(req), sizeof(req));
	if (send(sock, &req, MIP_MSG_SIZE2(req), 0) == -1) {
		perror("send");
		exit(-1);
	}

	close(sock);
	return 0;
}