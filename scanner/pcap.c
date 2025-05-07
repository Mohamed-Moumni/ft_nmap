#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


int main(int ac, char *av[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *dev;
    struct pcap_pkthdr header;	/* The header that pcap gives us */
	const char *packet;		/* The actual packet */
    struct bpf_program fp;
    char filter_exp[] = "src host 18.154.84.103 and src port 443";
    bpf_u_int32 net = 0;
    bpf_u_int32 mask = 0;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return 1;
    }
    
    if (alldevs == NULL) {
        fprintf(stderr, "No devices found\n");
        return 1;
    }
    
    dev = alldevs;  // Use the first device

    if (dev->name == NULL) {
        fprintf(stderr, "First device has no name\n");
        pcap_freealldevs(alldevs);
        return 1;
    }
    
    printf("Using device: %s\n", dev->name);
    
    pcap_t *handle;
    
    handle = pcap_open_live(dev->name, 65535, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
        return(2);
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
    packet = pcap_next(handle, &header);

    const char *ip_header = packet + 14;
    struct ip *iph = (struct ip *)ip_header;

    int ip_header_len = iph->ip_hl * 4;
    const char *tcp_header = ip_header + ip_header_len;
    struct tcphdr *tcph = (struct tcphdr *)tcp_header;

    printf("soure Port: %d\n", ntohs(tcph->th_sport));
    printf("Destination Port: %d\n", ntohs(tcph->th_dport));
    pcap_close(handle);
}
