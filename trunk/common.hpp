#ifndef PMIP_COMMON_HPP
#define PMIP_COMMON_HPP

#include <asm/types.h>

__u64 ntohll(__u64 ll);
#define htonll ntohll
void randomize();
int popen2_ex(char **cmd, int *rfd, int *wfd);
void print_hex(char *buf, int len);
char *parse_progname(char *path);

#endif
