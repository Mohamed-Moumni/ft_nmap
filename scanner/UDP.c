#include "../ft_nmap.h"

int	udp_handler(int udp_sockfd)
{
	char buffer[4096];
	struct sockaddr_in reply_addr;
	socklen_t len = sizeof(reply_addr);
	ssize_t bytes_recv = recvfrom(udp_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&reply_addr, &len);
	if (bytes_recv < 0)
		return OPEN_FILTERED;
	return OPEN;
}

int	icmp_handler(int icmp_sockfd)
{
	char	buffer[4096];
	struct sockaddr_in reply_addr;
	socklen_t len = sizeof(reply_addr);
	ssize_t bytes_recv = recvfrom(icmp_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&reply_addr, &len);
	if (bytes_recv < 0)
		return OPEN_FILTERED;
	struct iphdr   *ip_hdr = (struct iphdr*)buffer;
	struct icmp_header *icmp_reply = (struct icmp_header *)(buffer + (ip_hdr->ihl * 4));
	if (icmp_reply->type == 3)
	{
		if (icmp_reply->code == 3)
			return CLOSED;

		return FILTERED;
	}
}

void generate_udp_header(struct udphdr *udp, uint16_t src_port, uint16_t dest_port, struct in_addr ip_source, struct in_addr ip_destination) {
	t_pseudo_header pseudo_header;
	char buf[2000];

    udp->source = htons(src_port);
    udp->dest = htons(dest_port);
    udp->len = htons(8);          // UDP length (header + data)

	pseudo_header.source_address = ip_source.s_addr;
    pseudo_header.dest_address = ip_destination.s_addr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.tcp_length = htons(sizeof(struct udphdr));

    memcpy(buf, &pseudo_header, sizeof(t_pseudo_header));
	memcpy(buf + sizeof(t_pseudo_header), udp, sizeof(struct udphdr));
    udp->check = checksum(buf, sizeof(t_pseudo_header) + sizeof(struct udphdr));
}

int udp_scan(char *ip, int port, int udp_sockfd)
{
    struct sockaddr_in	dest_addr;
    struct timeval  	tv;
	fd_set				readfds;
	int					maxfd;
	int					select_ret;
	struct ip			ip_header;
	struct udp			udp_header;
	struct sockaddr_in source_address = get_local_address();


	// Setup to send the udp packet
	generate_ip_header(&ip_header, source_address.sin_addr, tsock.socket.sin_addr);
    generate_udp_header(port, scan_type, probe, source_address.sin_addr, tsock.socket.sin_addr);
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = inet_addr(ip);
	ssize_t ret = sendto(udp_sockfd, "", 0, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
	if (ret  < 0)
	{
		printf("sendto error: %ld\n", ret);
		printf("errno: %d\n", errno);
		exit(1);
	}

	// Listen for both icmp or udp to receive the response
	select_ret = select(maxfd + 1, &readfds, NULL, NULL, &tv);
	if (select_ret == -1)
	{
		printf("select failed: %d\n", errno);
		exit(1);
	}
	else if (select_ret == 0)
		return OPEN_FILTERED;
	else
	{
		// Handle the udp response
		if (FD_ISSET(udp_sockfd, &readfds))
			return udp_handler(udp_sockfd);
		// Handle the icmp response
		if (FD_ISSET(icmp_sockfd, &readfds))
			return icmp_handler(icmp_sockfd);
	}
	return OPEN;
}
