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
	fprintf(stderr, "Usage: %s <command> [options]\n\
\n\
  available commands\n\
    add <spi> <secret> [-m|-s] [-t num|-n]\n\
                  add <spi> to sadb\n\
    del <spi>     delete entry <spi> from sadb\n\
    list [<spi>]  list entries in sadb\n\
    flush         flush sadb\n\
\n\
  available options\n\
    -m      using hmac-md5 for authentication\n\
    -s      using hmac-sha1 for authentication\n\
    -t num  using timestamp for replay protection\n\
            with 'num' seconds replay delay, default to 7\n\
    -n      using nonce for replay protection\n", 
 		progname);
	exit(-1);
}

int main(int argc, char** argv)
{
	char *p, c;
	char *hmac = "sha1";
	unsigned int replay = MIPSA_REPLAY_TIMESTAMP;
	unsigned int delay = 7;

	progname = argv[0];
	if ((p = strrchr(progname, '/')) != NULL)
		progname = p + 1;

	while ((c = getopt(argc, argv, "msnt:")) != -1) {
		switch (c) {
		case 'm':
			hmac = "md5";
			break;
		case 's':
			hmac = "sha1";
			break;
		case 'n':
			replay = MIPSA_REPLAY_NONCE;
			delay = 0;
			break;
		case 't':
			replay = MIPSA_REPLAY_TIMESTAMP;
			if (optarg != NULL && sscanf(optarg, "%u", &delay) != 1) {
				fprintf(stderr, "bad replay delay %s\n", optarg);
				usage();
			}
			break;
		default:
			usage();
		}
	}

	if (argc == 1)
		usage();

	if (argc == optind) {
		fprintf(stderr, "no command specified\n");
		usage();
	}
	char *cmd = argv[optind];

	unsigned long spi = 0;
	if (argc > optind + 1) {
		char *spistr = argv[optind + 1];
		if (sscanf(spistr, "%lu", &spi) != 1) {
			fprintf(stderr, "bad spi value %s\n", spistr);
			usage();
		}
	}

	if (strcmp(cmd, "add") == 0) {
		if (argc < optind + 3)
			usage();
		char *secret = argv[optind + 2];
		load_sadb();
		add_sa(spi, secret, hmac, replay, delay);
		save_sadb();
	}
	else if (strcmp(cmd, "del") == 0) {
		if (argc < optind + 2)
			usage();
		load_sadb();
		if (del_sa(spi) == 0)
			printf("%lu removed from sadb\n", spi);
		else
			printf("%lu not found in sadb\n", spi);
		save_sadb();
	}
	else if (strcmp(cmd, "list") == 0) {
		load_sadb();
		list_sa(spi);
	}
	else if (strcmp(cmd, "flush") == 0) {
		flush_sadb();
	}
	else {
		fprintf(stderr, "bad command %s\n", argv[1]);
		usage();
	}

	return 0;
}
