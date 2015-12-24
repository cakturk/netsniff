/*
 * Copyright (C) 2015 Cihangir Akturk
 */
#ifndef _NETSNIF_H_
#define _NETSNIF_H_

/* Linux specific header. Fix this include for other UNIX systems */
#include <endian.h>
#include <stdint.h>

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

struct machdr {
	uint8_t	 dst[6];
	uint8_t	 src[6];
	uint16_t type;
};
#define mac_hdr(ptr) ((struct machdr *)(ptr))

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

int get_program_options(int argc, char **argv, struct program_options *opts);

#endif /* end of include guard: _NETSNIF_H_ */
