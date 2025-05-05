#include "../ft_nmap.h"

// Get TCP Header

// Get IP Header

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

void generate_ip_header(t_probe *probe_request, struct in_addr ip_source, struct in_addr ip_destination)
{
    probe_request->ip_header.ip_v = 4;
    probe_request->ip_header.ip_hl = 5;
    probe_request->ip_header.ip_tos = 0;
    probe_request->ip_header.ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    probe_request->ip_header.ip_id = 7793; // just static value for the moment
    probe_request->ip_header.ip_off = htons(0);
    probe_request->ip_header.ip_ttl = 128;
    probe_request->ip_header.ip_p = IPPROTO_TCP;
    probe_request->ip_header.ip_sum = htons(0);
    probe_request->ip_header.ip_src = ip_source;
    probe_request->ip_header.ip_dst = ip_destination;
    probe_request->ip_header.ip_sum = checksum((void *)(&probe_request->ip_header), sizeof(struct ip));
}

void generate_tcp_header(int port, t_probe *probe_request)
{
    probe_request->tcp_header.th_sport = htons(54321);
    probe_request->tcp_header.th_dport = htons(port);
    probe_request->tcp_header.th_seq = htons(223423);
    probe_request->tcp_header.th_ack = htons(0);
    probe_request->tcp_header.th_flags = TH_SYN;
    probe_request->tcp_header.th_sum = htons(0);
    probe_request->tcp_header.th_urp = htons(0);
    probe_request->tcp_header.th_win = htons(5840);
    probe_request->tcp_header.th_sum = checksum((void *)(&probe_request->tcp_header), sizeof(struct tcphdr));
}

struct sockaddr_in get_local_address(void)
{
    int                 sock;
    struct sockaddr_in  local_addr;
    socklen_t addr_len = sizeof(local_addr);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        printf("Socket Error: \n");
        exit(1);
    }
    getsockname(sock, (struct sockaddr *)&local_addr, &addr_len);
    return local_addr;
}

t_sock get_target_address(void)
{
    int     sock;
    t_sock tsock;
    struct sockaddr_in  dest_addr;
    socklen_t addr_len = sizeof(dest_addr);

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dest_addr.sin_addr);
    tsock.socket = dest_addr;
    tsock.socket_len = addr_len;
    return tsock;
}

int main(void)
{
    int tcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    
    if (tcp_socket == -1)
    {
        printf("Socket Creation Error\n");
        exit(1);
    }
    t_probe *probe;
    char    data[1024];
    char    data_to_send[1024];
    struct sockaddr_in source_address;
    t_sock tsock;
    char *error;

    memset(data_to_send, 0, 1024);
    probe = malloc(sizeof(t_probe));
    source_address = get_local_address();
    tsock = get_target_address();
    int value = 1;
    // memset(data, 0, 1024);

    setsockopt(tcp_socket, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value));

    generate_ip_header(probe, source_address.sin_addr, tsock.socket.sin_addr);
    generate_tcp_header(80, probe);
    // memcpy((void *)data_to_send, (void *)probe->ip_header, sizeof(struct ip));
    printf("%lu\n", sizeof(t_probe));
    int send_res = sendto(tcp_socket, (void *)probe, sizeof(t_probe), 0,(struct sockaddr *)&tsock.socket, tsock.socket_len);
    if (send_res < 0)
    {
        perror(error);
        print_error("sendto error: %s", strerror(send_res));
        exit(1);
    }

    // int recv_res = recvfrom(tcp_socket, data, 1024, 0, (struct sockaddr *)&tsock.socket, &tsock.socket_len);
    // if (recv_res < 0)
    // {
    //     print_error("recvfrom error:");
    //     exit(1);
    // }
    // printf("Hello");
}