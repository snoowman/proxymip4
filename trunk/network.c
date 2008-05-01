#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "common.h"
#include "network.h"

int tunnel_name(char *buf, size_t size, in_addr_t raddr)
{
	return snprintf(buf, size, "mit%08x", raddr);
}

int create_tunnel(char *tif, in_addr_t laddr, in_addr_t raddr)
{
	struct in_addr addr;

	addr.s_addr = laddr;
	char local[20];
	snprintf(local, 20, "%s", inet_ntoa(addr));

	addr.s_addr = raddr;
	char remote[20];
	snprintf(remote, 20, "%s", inet_ntoa(addr));

	char cmd[1024];
	snprintf(cmd, 1024, "ip tunnel add %s mode ipip remote %s local %s", tif, remote, local);
	int ret = system(cmd);
	if (ret < 0)
		return ret;
	
	snprintf(cmd, 1024, "ifconfig %s 0.0.0.0 up", tif);
	return system(cmd);
}

int release_tunnel(char *tif)
{
	char cmd[1024];
	snprintf(cmd, 1024, "ip tunnel del %s", tif);
	return system(cmd);
}

int register_hoa(in_addr_t hoa, char *tif, char *hif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	char cmd[1024];
	snprintf(cmd, 1024, "ip route add %s/32 dev %s", mnaddr, tif);
	int ret = system(cmd);
	if (ret < 0)
		return ret;
	
	snprintf(cmd, 1024, "arp -n -Ds %s %s pub", mnaddr, hif);
	return system(cmd);
}

int deregister_hoa(in_addr_t hoa, char *tif, char *hif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	char cmd[1024];
	snprintf(cmd, 1024, "arp -n -d %s -i %s pub", mnaddr, hif);
	int ret = system(cmd);
	if (ret < 0)
		return ret;
	
	snprintf(cmd, 1024, "ip route add %s/32 dev %s", mnaddr, tif);
	return system(cmd);
}	

int table_index(char *tif)
{
	// TODO allocate real table index
	int ret = in_cksum(tif, strlen(tif));
	ret = 1 + ret % 250;
	return ret; 
}

int set_proxy_arp(char *mif, int flag)
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

int register_route_to_tunnel(char *tif, int tab)
{
	char cmd[1024];
	snprintf(cmd, 1024, "ip route add default dev %s table %d", tif, tab);
	return system(cmd);
}

int unregister_route_to_tunnel(char *tif, int tab)
{
	char cmd[1024];
	snprintf(cmd, 1024, "ip route del default dev %s table %d", tif, tab);
	return system(cmd);
}

int register_source_route(in_addr_t hoa, int tab, char *mif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	char cmd[1024];
	snprintf(cmd, 1024, "ip route add %s/32 dev %s", mnaddr, mif);
	int ret = system(cmd);
	if (ret < 0)
		return ret;
	
	snprintf(cmd, 1024, "ip rule add from %s/32 lookup %d", mnaddr, tab);
	return system(cmd);
}

int unregister_source_route(in_addr_t hoa, int tab, char *mif)
{
	struct in_addr addr;
	addr.s_addr = hoa;
	char mnaddr[20];
	sprintf(mnaddr, "%s", inet_ntoa(addr));

	char cmd[1024];
	snprintf(cmd, 1024, "ip route del %s/32 dev %s", mnaddr, mif);
	int ret = system(cmd);
	if (ret < 0)
		return ret;
	
	snprintf(cmd, 1024, "ip rule del from %s/32 lookup %d", mnaddr, tab);
	return system(cmd);
}
