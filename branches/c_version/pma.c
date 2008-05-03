#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

#include "common.h"
#include "rfc1256.h"
#include "rfc3344.h"
#include "sadb.h"
#include "network.h"

char *progname;

static void usage()
{
	fprintf(stderr, "Usage: %s -m <hoa> -c <coa> -h <ha> -s <spi> -i <if> -l <life>\n\
  -m   register home address 'hoa'\n\
  -c   using care-of address 'coa'\n\
  -h   register with home agent 'ha'\n\
  -l   lifetime, default to 0xfffe\n\
  -i   link 'if' which mn reside\n\
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

int verify_reply(struct mip_reg_reply *rep, int plen, struct sockaddr_in *hoa)
{
	if (rep->type != MIP_REPLY_TYPE) {
		fprintf(stderr, "incorrect MIP type value %d\n", rep->type);
		exit(-1);
	}

	if (plen != MIP_MSG_SIZE2(*rep)) {
		fprintf(stderr, "incorrect packet length %d\n", plen);
		exit(-1);
	}

	if (rep->hoa != hoa->sin_addr.s_addr) {
		fprintf(stderr, "incorrect home address %08x, %08x\n", rep->hoa, hoa->sin_addr.s_addr);
		exit(-1);
	}

	struct mipsa *sa = find_sa(ntohl(rep->auth.spi));
	if (!sa) {
		fprintf(stderr, "incorrect spi %u\n", ntohl(rep->auth.spi));
		exit(-1);
	}

	int authlen = authlen_by_sa(sa);
	if (authlen != rep->auth.length) {
		fprintf(stderr, "incorrect auth length %d", authlen);
		exit(-1);
	}

	if (!verify_by_sa(rep->auth.auth, rep, MIP_MSG_SIZE1(*rep), sa)) {
		fprintf(stderr, "reply failed authentication\n");
		exit(-1);
	}

	// TODO check id
	
	if (rep->code != MIPCODE_ACCEPT)
		return rep->code;

	return 0;
}

int main(int argc, char** argv)
{
	char *p, c, tmp;
	char *hoa = NULL;
	char *ha = NULL;
	char *coa = NULL;
	char *mn_ifname = NULL;
	__u32 spi = 0;
	__u16 lifetime = 0xfffe;

	progname = argv[0];
	if ((p = strrchr(progname, '/')) != NULL)
		progname = p + 1;

	while ((c = getopt(argc, argv, "h:m:c:s:l:i:")) != -1) {
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
		case 'i':
			mn_ifname = optarg;
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

	if (mn_ifname == NULL || strlen(mn_ifname) == 0)
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

	// test mn_ifname
	sock_get_if_index(sock, mn_ifname);

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

	if (sendto(sock, &req, MIP_MSG_SIZE2(req), 0, (struct sockaddr *)&sa_ha, sizeof(sa_ha)) == -1) {
		perror("send");
		exit(-1);
	}

	struct mip_reg_reply rep;
	int plen = recv(sock, &rep, sizeof(rep), 0);
	if (plen == -1) {
		perror("recv");
		exit(-1);
	}
	close(sock);

	int ret = verify_reply(&rep, plen, &sa_hoa);
	if (ret != 0) {
		fprintf(stderr, "reply code = %d, registration failed\n", rep.code);
		exit(-1);
	}

	char tif[IFNAMSIZ];
	tunnel_name(tif, IFNAMSIZ, rep.ha);
	int tab = table_index(tif);

	// handle deregistration sucess
	if (lifetime == 0) {
		unregister_source_route(req.hoa, tab, mn_ifname);
		set_proxy_arp(mn_ifname, 0);
		unregister_route_to_tunnel(tif, tab);
		release_tunnel(tif);
	} 
	// handle registration success
	else {
		create_tunnel(tif, req.coa, rep.ha);
		register_route_to_tunnel(tif, tab);
		set_proxy_arp(mn_ifname, 1);
		register_source_route(req.hoa, tab, mn_ifname);
	}

	return 0;
}
