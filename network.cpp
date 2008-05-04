#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "network.hpp"

int my_system(char const *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char cmd[1024];
	vsnprintf(cmd, 1000, fmt, ap);
	va_end(ap);

	syslog(LOG_DEBUG, "executing \"%s\"", cmd);
	int ret =  system(cmd);
	if (ret != 0)
		syslog(LOG_WARNING, "previous command exited with code %d", ret);
	return ret;
}

char *tunnel_name(in_addr_t raddr)
{
	static char buf[IFNAMSIZ];
	snprintf(buf, IFNAMSIZ - 1, "mit%08x", raddr);
	return buf;
}

int create_tunnel(in_addr_t laddr, in_addr_t raddr)
{
	struct in_addr addr;

	addr.s_addr = laddr;
	char local[20];
	snprintf(local, 20, "%s", inet_ntoa(addr));

	addr.s_addr = raddr;
	char remote[20];
	snprintf(remote, 20, "%s", inet_ntoa(addr));

	my_system("ip tunnel add %s mode ipip remote %s local %s", tunnel_name(raddr), remote, local);
	my_system("ifconfig %s 0.0.0.0 up", tunnel_name(raddr));
	return 0;
}

int release_tunnel(in_addr_t raddr)
{
	my_system("ip tunnel del %s", tunnel_name(raddr));
	return 0;
}

int register_hoa(in_addr_t hoa, in_addr_t coa, char const *hif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	my_system("ip route add %s/32 dev %s", mnaddr, tunnel_name(coa));
	my_system("arp -n -Ds %s %s pub", mnaddr, hif);
	return 0;
}

int deregister_hoa(in_addr_t hoa, in_addr_t coa, char const *hif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	my_system("arp -n -d %s -i %s pub", mnaddr, hif);
	my_system("ip route del %s/32 dev %s", mnaddr, tunnel_name(coa));
	return 0;
}	

int set_proxy_arp(char const *mif, int flag)
{
	char proc[1024];

	snprintf(proc, 1024, "/proc/sys/net/ipv4/conf/%s/proxy_arp", mif);

	FILE *fp = fopen(proc, "w");
	if (fp == NULL)
		return -1;
	
	int c = (flag)? '1':'0';
	fputc(c, fp);
	fclose(fp);

	return 0;
}

int register_route_to_tunnel(in_addr_t ha, int tab)
{
	my_system("ip route add default dev %s table %d", tunnel_name(ha), tab);
	return 0;
}

int unregister_route_to_tunnel(in_addr_t ha, int tab)
{
	my_system("ip route del default dev %s table %d", tunnel_name(ha), tab);
	return 0;
}

int register_source_route(in_addr_t hoa, int tab, char const *mif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	my_system("ip route add %s/32 dev %s", mnaddr, mif);
	my_system("ip rule add from %s/32 lookup %d", mnaddr, tab);
	return 0;
}

int unregister_source_route(in_addr_t hoa, int tab, char const *mif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	my_system("ip route del %s/32 dev %s", mnaddr, mif);
	my_system("ip rule del from %s/32 lookup %d", mnaddr, tab);
	return 0;
}

