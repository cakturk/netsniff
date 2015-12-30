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
const char *
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

static char fmt_buf[1024];

static struct strbuf sb = {
	.size = sizeof(fmt_buf),
	.buf = fmt_buf,
};

static void
pkt_handler(u_char *usr, const struct pcap_pkthdr *pkt, const u_char *d)
{
	struct machdr *mac = mac_hdr(d);
	struct iphdr *ip;
	struct tcphdr *th;
	struct udphdr *uh;

	sb_reset(&sb);
	eth_print(mac, &sb);

	switch (ntohs(mac->type)) {
	case ETH_P_IP:
		ip = ip_hdr(d + ETH_HLEN);
		sb_append_str(&sb, "; IP: ");
		iphdr_print(ip, &sb);

		switch (ip->protocol) {
		case IPPROTO_TCP:
			th = tcp_hdr(d + ETH_HLEN + ip_hdrlen(ip));
			sb_append_str(&sb, "; TCP: ");
			tcp_print(th, &sb);
			break;

		case IPPROTO_UDP:
			uh = udp_hdr(d + ETH_HLEN + ip_hdrlen(ip));
			sb_append_str(&sb, "; UDP: ");
			udp_print(uh, &sb);
			break;

		default:
			sb_append_char(&sb, ' ');
			sb_append_nullstr(&sb, ipproto_str(ip->protocol));
		}

		break;
	default:
		fprintf(stdout, "ether type: 0x%04x, %s\n",
			ntohs(mac->type), ethertype_to_str(ntohs(mac->type)));
		return;
	}
	sb_append_null(&sb);
	fprintf(stdout, "pkt: %s\n", sb.buf);
}
