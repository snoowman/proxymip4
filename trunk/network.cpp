#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
//#include "common.h"
#include "network.hpp"

int my_system(char const* cmd)
{
	printf("%s\n", cmd);
	return system(cmd);
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

	char cmd[1024];
	snprintf(cmd, 1024, "ip tunnel add %s mode ipip remote %s local %s", tunnel_name(raddr), remote, local);
	int ret = my_system(cmd);
	if (ret < 0)
		return ret;
	
	snprintf(cmd, 1024, "ifconfig %s 0.0.0.0 up", tunnel_name(raddr));
	return my_system(cmd);
}

int release_tunnel(in_addr_t raddr)
{
	char cmd[1024];
	snprintf(cmd, 1024, "ip tunnel del %s", tunnel_name(raddr));
	return my_system(cmd);
}

int register_hoa(in_addr_t hoa, in_addr_t coa, char const *hif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	char cmd[1024];
	snprintf(cmd, 1024, "ip route add %s/32 dev %s", mnaddr, tunnel_name(coa));
	int ret = my_system(cmd);
	if (ret < 0)
		return ret;
	
	snprintf(cmd, 1024, "arp -n -Ds %s %s pub", mnaddr, hif);
	return my_system(cmd);
}

int deregister_hoa(in_addr_t hoa, in_addr_t coa, char const *hif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	char cmd[1024];
	snprintf(cmd, 1024, "arp -n -d %s -i %s pub", mnaddr, hif);
	int ret = my_system(cmd);
	if (ret < 0)
		return ret;
	
	snprintf(cmd, 1024, "ip route del %s/32 dev %s", mnaddr, tunnel_name(coa));
	return my_system(cmd);
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
	char cmd[1024];
	snprintf(cmd, 1024, "ip route add default dev %s table %d", tunnel_name(ha), tab);
	return my_system(cmd);
}

int unregister_route_to_tunnel(in_addr_t ha, int tab)
{
	char cmd[1024];
	snprintf(cmd, 1024, "ip route del default dev %s table %d", tunnel_name(ha), tab);
	return my_system(cmd);
}

int register_source_route(in_addr_t hoa, int tab, char const *mif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	char cmd[1024];
	snprintf(cmd, 1024, "ip route add %s/32 dev %s", mnaddr, mif);
	int ret = my_system(cmd);
	if (ret < 0)
		return ret;
	
	snprintf(cmd, 1024, "ip rule add from %s/32 lookup %d", mnaddr, tab);
	return my_system(cmd);
}

int unregister_source_route(in_addr_t hoa, int tab, char const *mif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	char cmd[1024];
	snprintf(cmd, 1024, "ip route del %s/32 dev %s", mnaddr, mif);
	int ret = my_system(cmd);
	if (ret < 0)
		return ret;
	
	snprintf(cmd, 1024, "ip rule del from %s/32 lookup %d", mnaddr, tab);
	return my_system(cmd);
}

