#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include <fstream>
#include <string>
#include <boost/lexical_cast.hpp>

int main(int argc, char **argv)
{
  if (argc != 3) {
    printf("Usage: %s <ifname> <microsec>\n", argv[0]);
    return -1;
  }

  std::string target = std::string(argv[1]) + ":";
  unsigned int interval = boost::lexical_cast<unsigned int>(argv[2]);

  unsigned long long orx = 0LLU, otx = 0LLU;
  while (1) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    printf("%u.%06u ", tv.tv_sec, tv.tv_usec);
    std::ifstream ifs("/proc/net/dev");
    while (ifs) {
      std::string str;
      ifs >> str;
      if (str.substr(0, target.length()) == target) {
        unsigned long long rx, tx, unused;
	if (str.length() > target.length()) 
	  rx = boost::lexical_cast<unsigned long long>(str.substr(target.length()));
	else
          ifs >> rx;
        ifs >> unused >> unused >> unused >> unused >> unused >> unused >> unused;
        ifs >> tx;
        printf("%llu %llu\n", rx - orx, tx - otx);
        fflush(stdout);
	orx = rx;
	otx = tx;
      }
    }
    usleep(interval);
  }
  return 0;
}
