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

  unsigned int orx = 0u, otx = 0u;
  while (1) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    printf("%lu.%06lu ", tv.tv_sec, tv.tv_usec);
    std::ifstream ifs("/proc/net/dev");
    while (ifs) {
      std::string str;
      ifs >> str;
      if (str.substr(0, target.length()) == target) {
        unsigned int rx, tx, unused;
	if (str.length() > target.length()) 
	  rx = boost::lexical_cast<unsigned int>(str.substr(target.length()));
	else
          ifs >> rx;
        ifs >> unused >> unused >> unused >> unused >> unused >> unused >> unused;
        ifs >> tx;
        printf("%u %u\n", rx - orx, tx - otx);
        fflush(stdout);
	orx = rx;
	otx = tx;
      }
    }
    usleep(interval);
  }
  return 0;
}
