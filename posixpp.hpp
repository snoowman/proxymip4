#ifndef PMIP_POSIXPP_HPP
#define PMIP_POSIXPP_HPP

#include <stdexcept>
#include <string>
#include <string.h>
#include <errno.h>

class posix_error : public std::runtime_error {
  int err_;

public:
  explicit posix_error(int err, char *prefix)
    : runtime_error(std::string(prefix) + ": " + strerror(err)),
      err_(err)
  { }
};

template <typename T>
inline T except_wrapper(T ret, T val, char *prefix)
{
  if (ret == val)
    throw posix_error(errno, prefix);
  return ret;
}

#define socket_ex(arglist...) except_wrapper(::socket(arglist), -1, "socket")
#define close_ex(arglist...) except_wrapper(::close(arglist), -1, "close")
#define inet_aton_ex(arglist...) except_wrapper(::inet_aton(arglist), -1, "inet_aton")
#define send_ex(arglist...) except_wrapper(::send(arglist), -1, "send")
#define recv_ex(arglist...) except_wrapper(::recv(arglist), -1, "recv")
#define sendto_ex(arglist...) except_wrapper(::sendto(arglist), -1, "sendto")
#define recvfrom_ex(arglist...) except_wrapper(::recvfrom(arglist), -1, "recvfrom")
#define bind_ex(arglist...) except_wrapper(::bind(arglist), -1, "bind")
#define select_ex(arglist...) except_wrapper(::select(arglist), -1, "select")
#define open_ex(arglist...) except_wrapper(::open(arglist), -1, "open")
#define close_ex(arglist...) except_wrapper(::close(arglist), -1, "close")
#define dup2_ex(arglist...) except_wrapper(::dup2(arglist), -1, "dup2")
#define read_ex(arglist...) except_wrapper(::read(arglist), -1, "read")
#define pipe_ex(arglist...) except_wrapper(::pipe(arglist), -1, "pipe")
#define fork_ex(arglist...) except_wrapper(::fork(arglist), -1, "fork")
#define execv_ex(arglist...) except_wrapper(::execv(arglist), -1, "execv")
#define write_ex(arglist...) except_wrapper(::write(arglist), -1, "write")

#define fopen_ex(arglist...) except_wrapper<FILE *>(::fopen(arglist), NULL, "fopen")
#define fclose_ex(arglist...) except_wrapper(::fclose(arglist), EOF, "fopen")

#define ioctl_ex2(subtype, arglist...) except_wrapper(::ioctl(arglist), -1, "ioctl:" subtype)
#define setsockopt_ex2(subtype, arglist...) except_wrapper(::setsockopt(arglist), -1, "setsockopt:" subtype)

#endif
