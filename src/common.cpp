#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include "common.hpp"
#include "posixpp.hpp"
#include "config.hpp"

void randomize()
{
  static int init = 0;
  if (init != 0)
    return;

  init = 1;
  int fd = open_ex("/dev/urandom", O_RDONLY);
  unsigned int seed;
  if (read_ex(fd, &seed, sizeof(seed)) != sizeof(seed))
    seed = time(NULL);
  close_ex(fd);
  srand(seed);
}

int popen2_ex(char **cmd, int *rfd, int *wfd)
{
  int stdin_fds[2];
  int stdout_fds[2];
  pid_t pid = 0;

  if (pipe_ex(stdin_fds) == -1)
    return -1;

  if (pipe_ex(stdout_fds) == -1)
    return -1;
  
  pid = fork_ex();
  if (pid == -1)
    return -1;
  
  if (pid == 0) {
    dup2_ex(stdout_fds[1], STDOUT_FILENO);
    dup2_ex(stdin_fds[0], STDIN_FILENO);
    close_ex(stdout_fds[1]);
    close_ex(stdout_fds[0]);
    close_ex(stdin_fds[1]);
    close_ex(stdin_fds[0]);
    execv_ex(cmd[0], cmd);
    exit(-1);
  }
  
  close_ex(stdout_fds[1]);
  close_ex(stdin_fds[0]);
  *rfd = stdout_fds[0];
  *wfd = stdin_fds[1];
  return 0;
}

__u64 ntohll(__u64 ll)
{
  __u32* s = (__u32*)&ll;

  __u64 ret;
  __u32* d = (__u32*)&ret;
  d[0] = ntohl(s[1]);
  d[1] = ntohl(s[0]);
  return ret;
}

void print_hex(char *buf, int len)
{
  int i;
  for (i = 0; i < len; ++i)
    printf("%02hhx ", buf[i]);
  printf("\n");
}

char *parse_progname(char *path)
{
  char *p;
  if ((p = strrchr(path, '/')) != NULL)
    return p + 1;
  return path;
}

static volatile int *signal_number = 0;
void signal_cb(int signo);

void daemonize(char const *progname, volatile int *psigno)
{
  if (getppid_ex() == 1)
  	return;

  signal_number = psigno;

  openlog(progname, 0, LOG_DAEMON);

  // setup signal
  signal(SIGTSTP, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);

  pid_t pid = fork_ex();
  if (pid)
    exit(0);

  setsid_ex();

  pid_t pid2 = fork_ex();
  if (pid2) { // write child's pid before exit
    char fn[1024];
    snprintf(fn, 1024, DAEMON_PID_FMT, progname);

    FILE *fp = fopen_ex(fn, "w");
    fprintf(fp, "%d\n", pid2);
    fclose_ex(fp);

    exit(0);
  }

  chdir_ex("/tmp");
  umask(0);
 
  close_ex(STDIN_FILENO);
  close_ex(STDOUT_FILENO);
  close_ex(STDERR_FILENO);

  //signal(SIGCHLD, SIG_IGN);
  signal(SIGHUP, signal_cb);
  signal(SIGUSR1, signal_cb);
  signal(SIGINT, signal_cb);
  signal(SIGQUIT, signal_cb);
  signal(SIGTERM, signal_cb);
}

void signal_cb(int signo)
{
  *signal_number = signo;
}

__u64 time_stamp()
{
  struct timeval tv;
  gettimeofday(&tv, NULL);
  __u64 ret;

  // NTP epoch time is 1900, Linux epoch time is 1970
  // we need to add those seconds
  tv.tv_sec += 25567u * 24u * 3600u;

  ret = rand() & ((1 << 12) - 1);

  // for lower 32 bit
  //     top 20 bits (12 ~ 31) represent microsecond
  //   difference between 2^20 and 1 million ignored
  //     bottom 0 - 11 bits generated by rand
  ret |= (__u64)tv.tv_usec << 12;
  ret |= (__u64)tv.tv_sec << 32;

  return ret;
}

