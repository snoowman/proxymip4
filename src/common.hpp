#ifndef PMIP_COMMON_HPP
#define PMIP_COMMON_HPP

#include <asm/types.h>
#include <signal.h>

__u64 ntohll(__u64 ll);
#define htonll ntohll
void randomize();
int popen2_ex(char **cmd, int *rfd, int *wfd);
void print_hex(char *buf, int len);
char *parse_progname(char *path);
void daemonize(char const* progname, volatile int *psigno);
__u64 time_stamp();


#endif
