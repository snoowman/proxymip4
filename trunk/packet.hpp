#ifndef PMIP_PACKET_HPP
#define PMIP_PACKET_HPP

#include <stdexcept>
#include <string>

namespace packet {

size_t const MTU = 1500;

class bad_packet : public std::runtime_error {
public:
  bad_packet(std::string msg)
    : runtime_error("bad packet: " + msg)
  { }
};

class invalid_length : public std::logic_error {
public:
  invalid_length()
    : logic_error("invalid packet length")
  { }
};

inline unsigned short in_cksum(void *addr, int len) {
  int nleft = len;
  int sum = 0;
  __u16 *w = (__u16 *)addr;
  __u16 answer = 0;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    *(__u8 *)(&answer) = *(__u8 *)w;
    sum += answer;
  }

  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return (answer);
}

}

#endif
