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
#include "sadb.h"

char *progname;

static void usage()
{
	fprintf(stderr, "Usage: %s -m <hoa> -c <coa> -m <ha> -s <spi> -l <life>\n\
  -m   register home address 'hoa'\n\
  -c   using care-of address 'coa'\n\
  -h   register with home agent 'ha'\n\
  -l   lifetime, default to 0xfffe\n\
  -s   spi index for regstration\n",
 		progname);
	exit(-1);
}

void create_reg_request(struct mip_reg_request *req, struct sockaddr_in *hoa, struct sockaddr_in *ha, struct sockaddr_in *coa, struct mipsa *sa, __u16 lifetime)
{
	bzero(req, sizeof(*req));
	req->type = MIP_REQUEST_TYPE;
	req->flag_T = 1;
	req->lifetime = htons(lifetime);

	req->hoa = hoa->sin_addr.s_addr;
	req->ha = ha->sin_addr.s_addr;
	req->coa = coa->sin_addr.s_addr;
	req->id = htonll(id_by_sa(sa));

	req->auth.type = MIPEXT_AUTH_TYPE;
	req->auth.spi = htonl(sa->spi);

	req->auth.length = authlen_by_sa(sa);
	auth_by_sa(req->auth.auth, req, MIP_MSG_SIZE1(*req), sa);
}

int main(int argc, char** argv)
{
	char *p, c, tmp;
	char *hoa = NULL;
	char *ha = NULL;
	char *coa = NULL;
	__u32 spi = 0;
	__u16 lifetime = 0xfffe;

	progname = argv[0];
	if ((p = strrchr(progname, '/')) != NULL)
		progname = p + 1;

	while ((c = getopt(argc, argv, "h:m:c:s:l:")) != -1) {
		switch (c) {
		case 'h':
			ha = optarg;
			break;
		case 'm':
			hoa = optarg;
			break;
		case 'c':
			coa = optarg;
			break;
		case 'l':
			if (sscanf(optarg, "%hu%c", &lifetime, &tmp) != 1) {
				fprintf(stderr, "bad lifetime value %s\n", optarg);
				exit(-1);
			}
			break;
		case 's':
			if (sscanf(optarg, "%u%c", &spi, &tmp) != 1) {
				fprintf(stderr, "bad spi value %s\n", optarg);
				exit(-1);
			}
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
	
	if (spi < 256) {
		fprintf(stderr, "error, no spi specified or spi value below 256\n");
		exit(-1);
	}

	load_sadb();
	struct mipsa *sa = find_sa(spi);

	if (!sa) {
		fprintf(stderr, "error, no sa with specified spi %u exists\n", spi);
		exit(-1);
	}

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

	randomize();
	struct mip_reg_request req;
	create_reg_request(&req, &sa_hoa, &sa_ha, &sa_coa, sa, lifetime);

	if (send(sock, &req, MIP_MSG_SIZE2(req), 0) == -1) {
		perror("send");
		exit(-1);
	}

	close(sock);
	return 0;
}
