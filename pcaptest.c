#include <stdio.h>
#include <string.h>
#include <pcap.h>

#define eth_hdr(d) ((struct ethhdr *)d)

struct ethhdr {
	u_char  dst[6];
	u_char  src[6];
	u_short type;
};

static const char *mac_str(u_char *addr, char *buf);
extern int get_program_options(int argc, char **argv, struct program_options *popts);

int main(int argc, char **argv)
{
	char *devname;
	char ebuf[PCAP_ERRBUF_SIZE];
	char llstr[6 * 3];
	const u_char *pload;
	pcap_t *dev;
	struct pcap_pkthdr hdr;
	struct ethhdr *machdr;
#if 0
	printf("%zu\n", sizeof(*machdr));
	return 0;
#endif
	int c = get_program_options(argc, argv, NULL);
	printf("get_program_options: %d\n", c);
	return 0;

	devname = pcap_lookupdev(ebuf);
	printf("errbuf: %s: %s\n", ebuf, devname);

	dev = pcap_open_live("enp0s25", PCAP_ERRBUF_SIZE, 1, 2000, ebuf);
	printf("dev: %p\n", dev);

	pload = pcap_next(dev, &hdr);
	ebuf[PCAP_ERRBUF_SIZE - 1] = '\0';
	printf("ploadptr: %p, hdrlen: %u\n", pload, hdr.len);

	machdr = eth_hdr(pload);
	printf("mac header: src: %s\n", mac_str(machdr->src, llstr));
	printf("mac header: dst: %s\n", mac_str(machdr->dst, llstr));

	return 0;
}

static const char *mac_str(u_char *addr, char *buf)
{
	char mac[sizeof("xx:xx:xx:xx:xx:xx")];

	sprintf(mac, "%02x:%02x:%02x:%02x:%02x:%02x",
		addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);

	return memcpy(buf, mac, sizeof(mac));
}
