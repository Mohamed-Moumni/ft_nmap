#include "../ft_nmap.h"

t_icmp_header craft_icmp_header(int seq)
{
	t_icmp_header icmp_header_to_return;

	icmp_header_to_return.type = ICMP_ECHO;
	icmp_header_to_return.code = 0;
	icmp_header_to_return.id = getpid();
	icmp_header_to_return.sequence = seq;
	icmp_header_to_return.checksum = 0;
	return icmp_header_to_return;
}

unsigned short checksum(void *b, int len)
{
	unsigned short *buf = b;
	unsigned int sum = 0;
	unsigned short result;

	while (len > 1) {
		sum += *buf++;
		len -=2;
	}

	if (len ==1) {
		sum += *(unsigned char *)buf;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;
	return result;
}

int send_recv(char *packet, t_icmp_header *icmp_header, char *ipaddr, struct sockaddr *sockaddr, socklen_t addr_len)
{
	// long long   start_time;
	char        buffer[4096];
	int			sockfd;

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (sockfd < 0)
	{
		printf("socket error %d\n", sockfd);
		return false;
	}
	// start_time = get_time();
	ssize_t ret = sendto(sockfd, packet, sizeof(icmp_header) + 56, 0, sockaddr, addr_len);
	if (ret  < 0)
	{
		printf("sendto error: %ld. ip addr: %s\n", ret, ipaddr);
		return false;
	}

	struct sockaddr_in reply_addr;
	socklen_t len = sizeof(reply_addr);
	ssize_t bytes_recv = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&reply_addr, &len);
	if (bytes_recv < 0)
	{
		printf("recvfrom error: %ld. ip addr: %s\n", bytes_recv, ipaddr);
		return false;
	}
	close(sockfd);
	struct iphdr   *ip_hdr = (struct iphdr*)buffer;
	struct icmp_header *icmp_reply = (struct icmp_header *)(buffer + (ip_hdr->ihl * 4));
	if (icmp_reply->type == ICMP_ECHOREPLY || icmp_reply->type == ICMP_ECHO)
		return true;
	return false;
}

bool host_discovery(char *ipaddr, struct sockaddr *sockaddr, socklen_t addr_len)
{
	t_icmp_header   icmp_header;
	char            packet[4095];
	char            random_data[] = "hoho teyoo jotaroo spinoza rigor giga matich ma3ert layer";
	char            *data;
	int				seq = 1;

	data = packet + sizeof(icmp_header);
	memset(data, 0, 56);
	memcpy(data, random_data, strlen(random_data));
	icmp_header = craft_icmp_header(seq);
	memcpy(packet, &icmp_header, sizeof(icmp_header));

	icmp_header.checksum = checksum((unsigned short *)packet, sizeof(icmp_header) + 56);
	memcpy(packet, &icmp_header, sizeof(icmp_header));
	memcpy(packet + sizeof(icmp_header), data, 56);
	return send_recv(packet, &icmp_header, ipaddr, sockaddr, addr_len);
}