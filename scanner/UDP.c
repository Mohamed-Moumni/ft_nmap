#include "../ft_nmap.h"

int	udp_handler(int udp_sockfd)
{
	char buffer[4096];
	struct sockaddr_in reply_addr;
	socklen_t len = sizeof(reply_addr);
	ssize_t bytes_recv = recvfrom(udp_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&reply_addr, &len);
	if (bytes_recv < 0)
	{
		printf("bytes recv: %ld errno: %d\n", bytes_recv, errno);
		return OPEN_FILTERED;
	}
	return OPEN;
}

int	icmp_handler(int icmp_sockfd)
{
	char	buffer[4096];
	struct sockaddr_in reply_addr;
	socklen_t len = sizeof(reply_addr);
	ssize_t bytes_recv = recvfrom(icmp_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&reply_addr, &len);
	if (bytes_recv < 0)
	{
		printf("bytes recv: %ld errno: %d\n", bytes_recv, errno);
		return OPEN_FILTERED;
	}
	struct iphdr   *ip_hdr = (struct iphdr*)buffer;
	struct icmp_header *icmp_reply = (struct icmp_header *)(buffer + (ip_hdr->ihl * 4));
	printf("icmp type: %d icmp code: %d\n", icmp_reply->type, icmp_reply->code);
	if (icmp_reply->type == 3)
	{
		if (icmp_reply->code == 3)
		{
			printf("closed\n");
			return CLOSED;
		}
		printf("filtered\n");
		return FILTERED;
	}
}

int udp_scan(char *ip, int port)
{
	double      		timer;
	int					udp_sockfd;
	int					icmp_sockfd;
    struct sockaddr_in	dest_addr;
    struct timeval  	tv;
	fd_set				readfds;
	int					maxfd;
	int					select_ret;

	// Socket prepration both icmp and udp socket
    tv.tv_sec = 5;
    tv.tv_usec = 0;
	FD_ZERO(&readfds);
	udp_sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (udp_sockfd < 0)
	{
		printf("socket error %d\n", udp_sockfd);
		exit(1);
	}
	FD_SET(udp_sockfd, &readfds);
	icmp_sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if (icmp_sockfd < 0)
	{
		printf("socket error %d\n", icmp_sockfd);
		exit(1);
	}
	FD_SET(icmp_sockfd, &readfds);
	maxfd = udp_sockfd > icmp_sockfd ? udp_sockfd : icmp_sockfd;

	// Setup to send the udp packet
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
	{
		printf("Time out the result is open|filtered \n");
		return OPEN_FILTERED;
	}
	else
	{
		// Handle the udp response
		if (FD_ISSET(udp_sockfd, &readfds))
		{
			printf("udp response\n");
			return udp_handler(udp_sockfd);
		}
		// Handle the icmp response
		if (FD_ISSET(icmp_sockfd, &readfds))
		{
			printf("icmp response\n");
			return icmp_handler(icmp_sockfd);
		}
	}
	return OPEN;
}
