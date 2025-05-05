#include "../ft_nmap.h"

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
    probe_request->ip_header.ip_id = 7793; // create a function that generate random number to set as an ID
    probe_request->ip_header.ip_off = htons(0);
    probe_request->ip_header.ip_ttl = TTL;
    probe_request->ip_header.ip_p = IPPROTO_TCP;
    probe_request->ip_header.ip_sum = 0;
    probe_request->ip_header.ip_src = ip_source;
    probe_request->ip_header.ip_dst = ip_destination;
    probe_request->ip_header.ip_sum = checksum((void *)(&probe_request->ip_header), sizeof(struct ip));
}

void generate_tcp_header(int port, t_probe *probe_request, struct in_addr ip_source, struct in_addr ip_destination)
{
    t_pseudo_header pseudo_header;
    char            buf[1024];

    memset(buf, 0, 1024);
    probe_request->tcp_header.th_sport = htons(12345); // generate a radnom number to set as source port
    probe_request->tcp_header.th_dport = htons(port);   
    probe_request->tcp_header.th_seq = htonl(0);
    probe_request->tcp_header.th_ack = 0;
    probe_request->tcp_header.th_off = 5;
    probe_request->tcp_header.th_flags = TH_SYN;     
    probe_request->tcp_header.th_win = htons(65535);    
    probe_request->tcp_header.th_sum = 0;
    probe_request->tcp_header.th_urp = 0;

    pseudo_header.source_address = ip_source.s_addr;
    pseudo_header.dest_address = ip_destination.s_addr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(sizeof(struct tcphdr));

    memcpy(buf, &pseudo_header, sizeof(t_pseudo_header));
    memcpy(buf + sizeof(t_pseudo_header), &probe_request->tcp_header, sizeof(struct tcphdr));

    probe_request->tcp_header.th_sum = checksum(buf, sizeof(t_pseudo_header) + sizeof(struct tcphdr));
}

struct sockaddr_in get_local_address(void)
{
    int                 sock;
    struct sockaddr_in  local_addr;
    struct sockaddr_in  dummy_dest;
    socklen_t addr_len = sizeof(local_addr);

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        perror("socket");
        exit(1);
    }

    memset(&dummy_dest, 0, sizeof(dummy_dest));
    dummy_dest.sin_family = AF_INET;
    dummy_dest.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dummy_dest.sin_addr);

    if (connect(sock, (struct sockaddr *)&dummy_dest, sizeof(dummy_dest)) < 0)
    {
        perror("connect");
        exit(1);
    }

    if (getsockname(sock, (struct sockaddr *)&local_addr, &addr_len) < 0)
    {
        perror("getsockname");
        exit(1);
    }

    close(sock);
    return local_addr;
}


t_sock get_target_address(char *target_addr, int port)
{
    int     sock;
    t_sock  tsock;
    struct  sockaddr_in  dest_addr;
    socklen_t addr_len = sizeof(dest_addr);

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    inet_pton(AF_INET, target_addr, &dest_addr.sin_addr);
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
    t_probe             *probe;
    char                data[1024];
    struct sockaddr_in  source_address;
    t_sock              tsock;

    memset(data, 0, 1024);
    probe = malloc(sizeof(t_probe));
    source_address = get_local_address();
    tsock = get_target_address("8.8.8.8", 443);
    int value = 1;

    setsockopt(tcp_socket, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value));

    generate_ip_header(probe, source_address.sin_addr, tsock.socket.sin_addr);
    generate_tcp_header(443, probe, source_address.sin_addr, tsock.socket.sin_addr);

    memcpy(data, &probe->ip_header, sizeof(struct ip));
    memcpy(data + sizeof(struct ip), &probe->tcp_header, sizeof(struct tcphdr));

    int send_res = sendto(tcp_socket, (void *)data, sizeof(struct ip) + sizeof(struct tcphdr), 0,(struct sockaddr *)&tsock.socket, tsock.socket_len);
    if (send_res < 0)
    {
        print_error("sendto error: %s", strerror(send_res));
        exit(1);
    }
    printf("Nice\n");
}