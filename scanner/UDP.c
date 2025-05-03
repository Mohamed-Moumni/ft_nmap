#include "../ft_nmap.h"

t_scan send_recv(char *ip, int port)
{
	double      timer;
	char        buffer[4096];
	int			sockfd;
    struct sockaddr_in dest_addr;
    struct timeval  tv;
	t_scan		to_return;

	to_return.type = UDP_SCAN;
	to_return.state = OPEN;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
	sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
	if (sockfd < 0)
	{
		printf("socket error %d\n", sockfd);
		exit(1);
	}
    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        printf("setsockopt failed\n");
		exit(1);
    }
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    dest_addr.sin_addr.s_addr = inet_addr(ip);
	ssize_t ret = sendto(sockfd, "", 0, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
	if (ret  < 0)
	{
		printf("sendto error: %ld\n", ret);
		exit(1);
	}
    struct sockaddr_in reply_addr;
	socklen_t len = sizeof(reply_addr);
	ssize_t bytes_recv = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&reply_addr, &len);
	if (bytes_recv < 0)
	{
		if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            printf("time out the result is open|filtered \n");
			to_return.state = OPEN_FILTERED;
            return to_return;
        }
		printf("recvfrom error: %ld. ip addr: %s\n", bytes_recv);
		to_return.state = OPEN_FILTERED;
		return to_return;
	}
	close(sockfd);
	return to_return;
}

int main()
{
    char    *ip = "8.8.8.8";
    int     port = "80";

    return 0;
}