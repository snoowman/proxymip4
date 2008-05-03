#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include "common.h"
#include "rfc3344.h"

__u16 in_cksum(void *addr, int len)
{
	int nleft = len;
	int sum = 0;
	__u16 *w = addr;
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

void randomize()
{
	int fd = open("/dev/urandom", O_RDONLY);
	unsigned int seed;
	if (read(fd, &seed, sizeof(seed)) < sizeof(seed))
		seed = time(NULL);
	close(fd);
	srand(seed);
}

void sock_set_icmpfilter(int sock, int type)
{
	struct icmp_filter filt;

	filt.data = ~(1 << type);
	if (setsockopt(sock, SOL_RAW, ICMP_FILTER,
			(char*)&filt, sizeof(filt)) == -1) {
		perror("WARNING: setsockopt(ICMP_FILTER)");
	}
}

void sock_join_mcast(int sock, in_addr_t mcast)
{
	struct in_addr tmp;
	tmp.s_addr = mcast;
	if (!IN_MULTICAST(mcast)) {
		fprintf(stderr, "internal error: %s not a multicast IP address\n", inet_ntoa(tmp));
		exit(-1);
	}

	struct ip_mreq mreq;
	bzero(&mreq, sizeof(mreq));
	mreq.imr_multiaddr.s_addr = htonl(mcast);
	mreq.imr_interface.s_addr = htonl(INADDR_ANY);
	if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == -1) {
		perror("setsockopt: IP_ADD_MEMBERSHIP");
		exit(1);
	}
}

void sock_bind_if(int sock, char *ifname)
{
	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, 
			ifname, strlen(ifname) + 1) == -1) {
		perror("setsockopt: SO_BINDTODEVICE");
		exit(-1);
	}
}

in_addr_t sock_get_if_addr(int sock, char *ifname)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	if (ioctl(sock, SIOCGIFADDR, &ifr) < 0) {
		perror("ioctl: SIOCGIFADDR");
		exit(-1);
	}

	if (ifr.ifr_addr.sa_family != AF_INET) {
		fprintf(stderr, "iface %s has no ip address\n", ifname);
		exit(-1);
	}

	struct sockaddr_in *sin = (struct sockaddr_in*)&ifr.ifr_addr;
	printf("if %s, addr %s\n", ifname, inet_ntoa(sin->sin_addr));
	return sin->sin_addr.s_addr;
}

int sock_get_if_index(int sock, char *ifname)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
		perror("ioctl: SIOCGIFADDR");
		exit(-1);
	}
	return ifr.ifr_ifindex;
}

int sock_get_if_prefix(int sock, char *ifname)
{
	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	if (ioctl(sock, SIOCGIFNETMASK, &ifr) < 0) {
		perror("ioctl: SIOCGIFADDR");
		exit(-1);
	}

	if (ifr.ifr_addr.sa_family != AF_INET) {
		fprintf(stderr, "iface %s has no netmask\n", ifname);
		exit(-1);
	}

	struct sockaddr_in *sin = (struct sockaddr_in*)&ifr.ifr_addr;
	printf("if %s, netmask %s\n", ifname, inet_ntoa(sin->sin_addr));

	in_addr_t mask = ntohl(sin->sin_addr.s_addr);
	int prefix = 0;

	int i;
	for (i = 31; i >= 0; --i) {
		if (!(mask & (1 << i)))
			break;
		++prefix;
	}
	return prefix;
}

int popen2(char **cmd, int *rfd, int *wfd)
{
	int stdin_fds[2];
	int stdout_fds[2];
	pid_t pid = 0;

	if (pipe(stdin_fds) == -1)
		return -1;

	if (pipe(stdout_fds) == -1)
		return -1;
	
	pid = fork();
	if (pid == -1)
		return -1;
	
	if (pid == 0) {
		dup2(stdout_fds[1], STDOUT_FILENO);
		dup2(stdin_fds[0], STDIN_FILENO);
		close(stdout_fds[1]);
		close(stdout_fds[0]);
		close(stdin_fds[1]);
		close(stdin_fds[0]);
		execv(cmd[0], cmd);
		exit(-1);
	}
	
	close(stdout_fds[1]);
	close(stdin_fds[0]);
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
	//         difference between 2^20 and 1 million ignored
	//     bottom 0 - 11 bits generated by rand
	ret |= (__u64)tv.tv_usec << 12;
	ret |= (__u64)tv.tv_sec << 32;

	return ret;
}

__u64 nonce()
{
	return 0ll;
}

void print_hex(char *buf, int len)
{
	int i;
	for (i = 0; i < len; ++i)
		printf("%02hhx ", buf[i]);
	printf("\n");
}
