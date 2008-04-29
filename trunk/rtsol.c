#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>

#include <arpa/inet.h>

#define ICMP_FILTER                     1

struct icmp_filter {
        __u32           data;
};

#define MAX_MTU 1500 /* random */

unsigned short in_cksum(unsigned short *addr, int len);

/* From Stevens, UNP2ev1 */
unsigned short
in_cksum(unsigned short *addr, int len)
{
    int nleft = len;
    int sum = 0;
    unsigned short *w = addr;
    unsigned short answer = 0;

    while (nleft > 1) {
        sum += *w++;
        nleft -= 2;
    }

    if (nleft == 1) {
        *(unsigned char *)(&answer) = *(unsigned char *)w;
        sum += answer;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

int
main(int argc, char **argv)
{
    /* ICMP variables */
    int ret = 0;
    int one = 1;
    int sock_icmp;
    struct sockaddr_in dst;
    struct ip *ip_hdr_out;
    struct icmp *icmp_hdr_out;
    char buf_in[MAX_MTU], buf_out[MAX_MTU];
    int ip_len;
    struct icmp_filter filt;

    /* hanoi variables */
    if ((sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0) {
        perror("socket");
        exit(1);
    }

    if ((ret = setsockopt(sock_icmp, IPPROTO_IP, IP_HDRINCL, (char *)&one,
                     sizeof(one))) < 0) {
        perror("setsockopt");
        exit(1);
    }

    filt.data = ~(1<<9);
    if (setsockopt(sock_icmp, SOL_RAW, ICMP_FILTER,
                    (char*)&filt, sizeof(filt)) == -1)
    {
        perror("WARNING: setsockopt(ICMP_FILTER)");
    }


    bzero(buf_out, MAX_MTU);
    ip_hdr_out   = (struct ip *)buf_out;
    icmp_hdr_out = (struct icmp *)(buf_out + sizeof(struct ip));
    ip_len = sizeof(struct ip) + 8;
    printf("ip_len (%d), ip (%d), icmp (%d)\n", ip_len, sizeof(struct ip), sizeof(struct icmp));

    /* Prepare outgoing IP header. */
    ip_hdr_out->ip_v          = 4;
    ip_hdr_out->ip_hl         = sizeof(struct ip) >> 2;
    ip_hdr_out->ip_tos        = 0;
    ip_hdr_out->ip_len        = htons(ip_len);
    ip_hdr_out->ip_id         = 0;
    ip_hdr_out->ip_off        = 0;
    ip_hdr_out->ip_ttl        = 255;
    ip_hdr_out->ip_p          = IPPROTO_ICMP;
    ip_hdr_out->ip_sum        = 0;
    ip_hdr_out->ip_src.s_addr = htonl(INADDR_LOOPBACK);
    ip_hdr_out->ip_dst.s_addr = htonl(INADDR_LOOPBACK);

    ip_hdr_out->ip_sum = in_cksum((unsigned short *)buf_out,
                                  sizeof(struct ip));

    /* Prepare outgoing ICMP header. */
    icmp_hdr_out->icmp_type  = 10;
    icmp_hdr_out->icmp_code  = 0;
    icmp_hdr_out->icmp_cksum = 0;
    
    icmp_hdr_out->icmp_cksum =
        in_cksum((unsigned short *)icmp_hdr_out, 8);

    bzero(&dst, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = ip_hdr_out->ip_dst.s_addr;

    ret = sendto(sock_icmp, buf_out, ip_len, 0,
                 (struct sockaddr *)&dst, sizeof(dst));

    if (ret < 0) {
        perror("sendto");
    }

    printf("ICMP_ROUTER_SOLICITATION sent\n");

    while(1) {
    	struct ip *ip_hdr_in;
    	struct icmp *icmp_hdr_in;

        if ((ret = recv(sock_icmp, buf_in, sizeof(buf_in), 0)) < 0) {
            perror("recv");
            exit(1);
        }

	if (ret < ip_len) {
            fprintf(stderr, "bad packet len (%d, %d)\n", ret, ip_len);
        }

    	ip_hdr_in   = (struct ip *)(buf_in);
        icmp_hdr_in = (struct icmp *)((unsigned char *)ip_hdr_in +
                                                   sizeof(struct ip));
	
	if (ip_hdr_in->ip_p == IPPROTO_ICMP && icmp_hdr_in->icmp_type == 9) {
            printf("ICMP_ROUTER_ADVERTISEMENT received\n");
	    break;
	}
    }

    close(sock_icmp);
} 

/* __END__ */
