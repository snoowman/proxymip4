#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "common.h"
#include "sadb.h"

#define MIPSADB_CONF "/etc/mip_sadb.conf"

struct mipsa *sadb = NULL;

void flush_sadb()
{
	struct mipsa *p = sadb;
	while(p) {
		struct mipsa *oldp = p;
		p = p->next;
		free(oldp);
	}
	sadb = NULL;
	FILE *fp = fopen(MIPSADB_CONF, "w");
	fclose(fp);
}

void load_sadb()
{
	if (sadb)
		return;

	FILE *fp = fopen(MIPSADB_CONF, "r");
	if (fp == NULL)
		return;

	struct mipsa** p = &sadb;
	while(!feof(fp)) {
		*p = malloc(sizeof(struct mipsa));
		if (p == NULL) {
			perror("malloc");
			exit(-1);
		}
		
		if (scan_sa(fp, *p) == -1) {
			free(*p);
			*p = NULL;
			break;
		}

		p = &((**p).next);
	}
	fclose(fp);
}

void save_sadb()
{
	FILE *fp = fopen(MIPSADB_CONF, "w");
	if (fp == NULL) {
		fprintf(stderr, "%s ", MIPSADB_CONF);
		perror("fopen");
		exit(-1);
	}

	struct mipsa *p = sadb;
	while(p) {
		print_sa(fp, p);

		struct mipsa *oldp = p;
		p = p->next;
		free(oldp);
	}
	sadb = NULL;
	fclose(fp);
}

struct mipsa *find_sa(unsigned long spi)
{
	struct mipsa *p = sadb;
	while(p) {
		if (p->spi == spi)
			return p;
		p = p->next;
	}
	return NULL;
}


int add_sa(unsigned long spi, char *secret, char *hmac, unsigned int replay, unsigned int delay)
{
	if (spi < 256) {
		fprintf(stderr, "spi (%lu) too small, spi 0-255 are reserved value\n", spi);
		exit(-1);
	}

	struct mipsa *sa = find_sa(spi);
	if (sa == NULL) {
		sa = malloc(sizeof(struct mipsa));
		if (sa == NULL) {
			perror("malloc");
			exit(-1);
		}
		sa->next = sadb;
		sadb = sa;
	}

	sa->spi = spi;
	strcpy(sa->secret, secret);
	strcpy(sa->hmac, hmac);
	sa->replay = replay;
	sa->delay = delay;

	return 0;
}

int del_sa(unsigned long spi)
{
	struct mipsa *p = sadb;
	struct mipsa *prev = NULL;
	while(p) {
		if (p->spi == spi)
			break;
		prev = p;
		p = p->next;
	}

	if (!p)
		return 1;
	if (p == sadb)
		sadb = sadb->next;
	else
		prev->next = p->next;
	free(p);

	return 0;
}

void list_sa(unsigned long spi)
{
	if (spi == 0) {
		struct mipsa *p = sadb;
		while(p) {
			print_sa(stdout, p);
			p = p->next;
		}
	}
	else {
		struct mipsa *sa = find_sa(spi);
		if (sa)
			print_sa(stdout, sa);
		else
			printf("no spi (%lu) found in sadb\n", spi);
	}
}

void print_sa(FILE *fp, struct mipsa *sa)
{
	char *replay;
	if (sa->replay == MIPSA_REPLAY_NONCE)
		replay = "nonce";
	else if (sa->replay == MIPSA_REPLAY_TIMESTAMP)
		replay = "timestamp";
	else
		replay = "badreplay";

	fprintf(fp, "spi:%lu hmac:%s secret:%s replay:%s delay:%u\n", sa->spi, sa->hmac, sa->secret, replay, sa->delay);
}

int scan_sa(FILE *fp, struct mipsa *sa)
{
	char replay[100];
	int ret = fscanf(fp, "spi:%lu hmac:%s secret:%s replay:%s delay:%u\n", &sa->spi, sa->hmac, sa->secret, replay, &sa->delay);
	if (ret == 0 || ret == EOF)
		return -1;
	else if (ret != 5) {
		fprintf(stderr, "bad sadb config format %d\n", ret);
		exit(-1);
	}

	if (sa->spi < 256) {
		fprintf(stderr, "spi (%lu) too small, spi 0-255 are reserved value\n", sa->spi);
		exit(-1);
	}

	if (strcmp(replay, "timestamp") == 0)
		sa->replay = MIPSA_REPLAY_TIMESTAMP;
	else if (strcmp(replay, "nonce") == 0)
		sa->replay = MIPSA_REPLAY_NONCE;
	else
		sa->replay = MIPSA_REPLAY_TIMESTAMP;
	return 0;
}

int auth_by_sa(char *auth, void *buf, ssize_t len, struct mipsa *sa)
{
	char *cmd[] = {"/usr/bin/openssl", sa->hmac,  "-binary", NULL};;
	int rfd, wfd;
	popen2(cmd, &rfd, &wfd);
	write(wfd, sa->secret, strlen(sa->secret));
	write(wfd, buf, len);
	close(wfd);
	int ret = read(rfd, auth, MIP_AUTH_MAX);
	close(rfd);
	return ret;
}

int verify_by_sa(char *old_auth, void *buf, ssize_t len, struct mipsa *sa)
{
	char auth[MIP_AUTH_MAX];
	int authlen = auth_by_sa(auth, buf, len, sa);
	if (memcmp(auth, old_auth, authlen - 4) == 0)
		return 1;
	return 0;
}

ssize_t authlen_by_sa(struct mipsa *sa)
{
	char auth[MIP_AUTH_MAX];
	int c = 0;
	ssize_t ret = auth_by_sa(auth, &c, sizeof(c), sa);
	return ret + 4;
}

