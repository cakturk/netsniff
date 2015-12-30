/*
 * Copyright (C) 2015 Cihangir Akturk
 */
#ifndef _NETSNIF_H_
#define _NETSNIF_H_

#if defined(__APPLE__)
#define __BYTE_ORDER __BYTE_ORDER__
#define __LITTLE_ENDIAN __ORDER_LITTLE_ENDIAN__
#define __BIG_ENDIAN __ORDER_BIG_ENDIAN__
#else
/* Linux specific header. Fix this include for other UNIX systems */
#include <endian.h>
#endif

#include <arpa/inet.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#if __BYTE_ORDER == __LITTLE_ENDIAN
#  define __LITTLE_ENDIAN_BITFIELD 1
#else
#  define __BIG_ENDIAN_BITFIELD 1
#endif

#define BPF_SZ 80

struct program_options {
	const char *interface;
	int	    snaplen;
	int	    count;
	int	    promisc;
	char	    bpf_expr[BPF_SZ];
};

struct strbuf {
	size_t  size;
	size_t  len;
	char   *buf;
};
#define sb_curr(sb) ((sb)->buf + (sb)->len)

static inline size_t sb_room(struct strbuf *sb)
{
	return sb->size - sb->len;
}
static inline void sb_append_char(struct strbuf *sb, char c)
{
	*(sb->buf + sb->len++) = c;
}
static inline void sb_append_str(struct strbuf *sb, const char *s)
{
	size_t len = strlen(s);
	memcpy(sb->buf + sb->len, s, len);
	sb->len =+ len;
	*sb_curr(sb) = '\0';
	++sb->len;
}
static inline void sb_append_nullstr(struct strbuf *sb, const char *s)
{
	sb_append_str(sb, s);
	sb->len =- 1;
}

#define ETH_ALEN 6        /* Octets in one ethernet addr   */
#define ETH_HLEN 14       /* Total octets in header.       */
#define ETH_ADDRSTRLEN 18 /* Total octets in header.       */

/* Ether protocols (type) */
#define ETH_P_IP        0x0800          /* Internet Protocol packet     */
#define ETH_P_ARP       0x0806          /* Address Resolution packet    */
#define ETH_P_DEC       0x6000          /* DEC Assigned proto           */
#define ETH_P_RARP      0x8035          /* Reverse Addr Res packet      */
#define ETH_P_IPV6      0x86DD          /* IPv6 over bluebook           */

struct machdr {
	uint8_t	 dst[ETH_ALEN];
	uint8_t	 src[ETH_ALEN];
	uint16_t type;
};
#define mac_hdr(ptr) ((struct machdr *)(ptr))

#define IP_RE           0x8000          /* Flag: "Reserved"             */
#define IP_DF           0x4000          /* Flag: "Don't Fragment"       */
#define IP_MF           0x2000          /* Flag: "More Fragments"       */
#define IP_OFFSET       0x1FFF          /* "Fragment Offset" part       */

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t	   ihl:4,
		   version:4;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t    version:4,
		   ihl:4;
#else
#error  "Please fix endianness macros"
#endif
	uint8_t	   tos;
	uint16_t   tot_len;
	uint16_t   id;
	uint16_t   frag_off;
	uint8_t	   ttl;
	uint8_t	   protocol;
	uint16_t   check;
	uint32_t   saddr;
	uint32_t   daddr;
};
#define ip_hdr(ptr) ((struct iphdr *)(ptr))

/* returns true if MF bit is set */
static inline int ip_mf(struct iphdr *iph)
{
	return !!(iph->frag_off & htons(IP_MF));
}
/* returns true if DF bit is set */
static inline int ip_df(struct iphdr *iph)
{
	return !!(iph->frag_off & htons(IP_DF));
}

int get_program_options(int argc, char **argv, struct program_options *opts);

#endif /* end of include guard: _NETSNIF_H_ */
