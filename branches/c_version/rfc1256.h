/*
 * http://tools.ietf.org/html/rfc1256
 */

#ifndef PMIP_RFC1256_H
#define PMIP_RFC1256_H

#define ICMP_ROUTER_SOLICITATION    10
#define ICMP_ROUTER_ADVERTISEMENT   9 

/* Router Variable */
#define DEFAULT_MAX_ADVERTISEMENT_INTERVAL          600
#define DEFAULT_MIN_ADVERTISEMENT_INTERVAL(maxintv) ((int) (0.75 * (maxintv)) )
#define DEFAULT_ADVERTISEMENT_LIFETIME(maxintv)     (3 * (maxintv))

#define IS_VALID_MAX_ADVERTISEMENT_INTERVAL(maxintv)\
		(maxintv >= 4 && maxintv <= 1800)

#define IS_VALID_MIN_ADVERTISEMENT_INTERVAL(minintv, maxintv)\
		(minintv >= 3 && minintv <= maxintv)

#define IS_VALID_ADVERTISEMENT_LIFETIME(lftm, maxintv)\
		(lftm >= maxintv && lftm <= 9000)

/* Router Constants */
#define MAX_INITIAL_ADVERT_INTERVAL 16
#define MAX_INITIAL_ADVERTISEMENTS  3
#define MAX_RESPONSE_DELAY          2

/* Host Constants */
#define MAX_SOLICITATION_DELAY 1
#define SOLICITATION_INTERVAL  3
#define MAX_SOLICITATIONS      3

#endif
