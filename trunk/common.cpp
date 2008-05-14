#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "common.hpp"
#include "posixpp.hpp"

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

void daemonize(char const *progname, sighandler_t handler)
{
  if (getppid_ex() == 1)
  	return;

  // setup signal
  signal(SIGTSTP, SIG_IGN);
  signal(SIGTTOU, SIG_IGN);
  signal(SIGTTIN, SIG_IGN);

  pid_t pid = fork_ex();
  if (pid)
    exit(0);

  setsid_ex();

  pid_t pid2 = fork_ex();
  if (pid2)
    exit(0);

  chdir_ex("/tmp");
  umask(0);
 
  close_ex(STDIN_FILENO);
  close_ex(STDOUT_FILENO);
  close_ex(STDERR_FILENO);

  //signal(SIGCHLD, SIG_IGN);
  signal(SIGHUP, handler);
  signal(SIGUSR1, handler);
  signal(SIGINT, handler);
  signal(SIGQUIT, handler);
  signal(SIGTERM, handler);
}
