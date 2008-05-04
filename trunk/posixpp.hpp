#ifndef PMIP_POSIXPP_HPP
#define PMIP_POSIXPP_HPP

#include <stdexcept>
#include <string>
#include <stdio.h>
#include <string.h>
#include <errno.h>

class posix_error : public std::runtime_error {
  int err_;

public:
  explicit posix_error(int err, char const *prefix, char const *postfix)
    : runtime_error(std::string(prefix) + strerror(err) + ", " + postfix),
      err_(err)
  { }
};

template <typename T>
inline T except_wrapper(T ret, T val, char const *pre, char const *file, int line, char const *func)
{
  if (ret == val) {
    static char buf[1000];
    sprintf(buf, "%s:%d:%s: ", file, line, pre);
    throw posix_error(errno, buf, func);
  }
  return ret;
}

#define socket_ex(arglist...) except_wrapper(::socket(arglist), -1, "socket", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define close_ex(arglist...) except_wrapper(::close(arglist), -1, "close", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define inet_aton_ex(arglist...) except_wrapper(::inet_aton(arglist), -1, "inet_aton", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define send_ex(arglist...) except_wrapper(::send(arglist), -1, "send", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define recv_ex(arglist...) except_wrapper(::recv(arglist), -1, "recv", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define sendto_ex(arglist...) except_wrapper(::sendto(arglist), -1, "sendto", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define recvfrom_ex(arglist...) except_wrapper(::recvfrom(arglist), -1, "recvfrom", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define bind_ex(arglist...) except_wrapper(::bind(arglist), -1, "bind", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define select_ex(arglist...) except_wrapper(::select(arglist), -1, "select", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define open_ex(arglist...) except_wrapper(::open(arglist), -1, "open", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define close_ex(arglist...) except_wrapper(::close(arglist), -1, "close", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define dup2_ex(arglist...) except_wrapper(::dup2(arglist), -1, "dup2", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define read_ex(arglist...) except_wrapper(::read(arglist), -1, "read", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define pipe_ex(arglist...) except_wrapper(::pipe(arglist), -1, "pipe", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define fork_ex(arglist...) except_wrapper(::fork(arglist), -1, "fork", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define execv_ex(arglist...) except_wrapper(::execv(arglist), -1, "execv", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define write_ex(arglist...) except_wrapper(::write(arglist), -1, "write", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define unlink_ex(arglist...) except_wrapper(::unlink(arglist), -1, "unlink", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define setsockopt_ex(arglist...) except_wrapper(::setsockopt(arglist), -1, "setsockopt", __FILE__, __LINE__, __PRETTY_FUNCTION__)

#define fopen_ex(arglist...) except_wrapper<FILE *>(::fopen(arglist), NULL, "fopen", __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define fclose_ex(arglist...) except_wrapper(::fclose(arglist), EOF, "fopen", __FILE__, __LINE__, __PRETTY_FUNCTION__)

#define ioctl_ex2(subtype, arglist...) except_wrapper(::ioctl(arglist), -1, "ioctl:" subtype, __FILE__, __LINE__, __PRETTY_FUNCTION__)
#define setsockopt_ex2(subtype, arglist...) except_wrapper(::setsockopt(arglist), -1, "setsockopt:" subtype, __FILE__, __LINE__, __PRETTY_FUNCTION__)

#endif
