/*
 * http://tools.ietf.org/html/rfc1256
 */

#ifndef PMIP_RFC1256_HPP
#define PMIP_RFC1256_HPP

#include <sys/time.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <stdexcept>
#include "common.hpp"
#include "sockpp.hpp"
#include "packet.hpp"

namespace rfc1256 {

/* ICMP Type */
int const ICMP_ROUTER_ADV = 9;
int const ICMP_ROUTER_SOL = 10;

/* Host Constants */
int const MaxSolDelay = 1;
int const SolInterval = 3;
int const MaxSolNum   = 3;

/* Router Constants */
int const MaxInitAdvInterval = 16;
int const MaxInitAdvNum      = 3;
int const MaxResponseDelay   = 2;

int const MaxAdvInterval_Default  = 600;
int const MaxAdvInterval_Min      = 4;
int const MaxAdvInterval_Max      = 1800;

double const MinAdvInterval_Ratio = 0.75L;
int const MinAdvInterval_Min      = 3;

int const AdvLifetime_Ratio       = 3L;
int const AdvLifetime_Max         = 9000;

/* Router Variable */
class router_vars {
  int max_adv_;
  int min_adv_;
  int adv_lifetime_;
  int seq_;

public:
  router_vars() {
    max_adv_ = -1;
    min_adv_ = -1;
    adv_lifetime_ = -1;
    seq_ = 0;
  }

  int max_adv_default() const {
    return MaxAdvInterval_Default;
  }

  int min_adv_default() const {
    return int(max_adv() * MinAdvInterval_Ratio + 0.5);
  }

  int adv_lifetime_default() const {
    return AdvLifetime_Ratio * max_adv();
  }

  int max_adv() const {
    if (max_adv_ == -1)
      return max_adv_default();
    return max_adv_;
  }

  int min_adv() const {
    if (min_adv_ == -1)
      return min_adv_default();
    return min_adv_;
  }

  int adv_lifetime() const {
    if (adv_lifetime_ == -1)
      return adv_lifetime_default();
    return adv_lifetime_;
  }

  void max_adv(int val) {
    if (val < MaxAdvInterval_Min || val > MaxAdvInterval_Max)
      throw std::range_error("MaxAdvInterval out of range");
    if (min_adv_ != -1 && val < min_adv_)
      throw std::range_error("MaxAdvInterval less than MinAdvInterval");
    if (adv_lifetime_ != -1 && val > adv_lifetime_)
      throw std::range_error("MaxAdvInterval greater than AdvLifetime");
    max_adv_ = val;
  }

  void min_adv(int val) {
    if (val < MinAdvInterval_Min || val > max_adv())
      throw std::range_error("MinAdvInterval out of range");
    min_adv_ = val;
  }

  void adv_lifetime(int val) {
    if (val < max_adv() || val > AdvLifetime_Max)
      throw std::range_error("AdvLifetime out fo range");
    min_adv_ = val;
  }

  timeval adv_interval() const {
    timeval tv;
    tv.tv_sec  = min_adv() + rand() % (max_adv() - min_adv());

    if (seq_ < MaxInitAdvNum && tv.tv_sec > MaxInitAdvInterval) {
      tv.tv_sec = MaxInitAdvInterval;
      tv.tv_usec = 0;
    }
    else {
      tv.tv_usec = rand() % 1000000;
    }

    return tv;
  }

  int increase_seq() {
    if (seq_ == 0)
      randomize();

    return seq_++;
  }
};

} // namespace rfc1256

#endif
