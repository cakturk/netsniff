#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "netsniff.h"

#define CAPTURE_INF -1

#define err_exit(msg) do {		\
	fprintf(stderr, "%s", msg);	\
	exit(EXIT_FAILURE);		\
} while (0)

static void
pkt_handler(u_char *, const struct pcap_pkthdr *, const u_char *);
static const char *
mac_str(char *__restrict buf, uint8_t *__restrict addr);

int main(int argc, char *argv[])
{
	static struct program_options opts;
	char errbuff[PCAP_ERRBUF_SIZE];
	pcap_t *pcap;
	int err;

	if (get_program_options(argc, argv, &opts))
		err_exit("could not get program options\n");

	if (!opts.interface)
		opts.interface = "any";

	pcap = pcap_open_live(opts.interface, opts.snaplen,
			      opts.promisc, 2000, errbuff);
	if (!pcap)
		err_exit("cannot open network interface\n");

	printf("datalink: %d\n", pcap_datalink(pcap));
	err = pcap_loop(pcap, CAPTURE_INF, pkt_handler, NULL);
	switch (err) {
		case 0:
			printf("netsniff terminated successfully\n");
			break;
		case -1:
		case -2:
			printf("netsniff terminated with error: %d\n", err);
			break;
	}

	exit(EXIT_SUCCESS);
}

static void
pkt_handler(u_char *usr, const struct pcap_pkthdr *pkt, const u_char *d)
{
	char macsrc[6 * 3];
	char macdst[6 * 3];
	char ipsrc[INET_ADDRSTRLEN];
	char ipdst[INET_ADDRSTRLEN];
	struct machdr *mac = mac_hdr(d);
	struct iphdr *ip;

	switch (ntohs(mac->type)) {
	case ETH_P_IP:
		ip = ip_hdr(d + ETH_HLEN);

		fprintf(stdout, "len: %u, caplen: %u, type: %04x "
			"%s->%s, IP: %s->%s, frag: %04x\n",
			pkt->len, pkt->caplen, ntohs(mac->type),
			mac_str(macdst, mac->dst), mac_str(macsrc, mac->src),
			inet_ntop(AF_INET, &ip->saddr, ipsrc, INET_ADDRSTRLEN),
			inet_ntop(AF_INET, &ip->daddr, ipdst, INET_ADDRSTRLEN),
			ntohs(ip->frag_off));
		break;
	default:
		fprintf(stdout, "ether type: 0x%04x\n", ntohs(mac->type));
	}
}

static const char *mac_str(char *__restrict buf, uint8_t *__restrict addr)
{
	sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	return buf;
}
