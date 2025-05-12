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

void generate_tcp_header(int port, int scan_type, t_probe *probe_request, struct in_addr ip_source, struct in_addr ip_destination)
{
    t_pseudo_header pseudo_header;
    char            buf[1024];

    memset(buf, 0, 1024);
    probe_request->tcp_header.th_sport = htons(12345); // generate a radnom number to set as source port
    probe_request->tcp_header.th_dport = htons(port);   
    probe_request->tcp_header.th_seq = htonl(0);
    probe_request->tcp_header.th_ack = 0;
    probe_request->tcp_header.th_off = 5;
    probe_request->tcp_header.th_flags = scan_type;     
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

bool check_time_out(struct timeval *start_time)
{
    struct timeval current_time;

    gettimeofday(&current_time, NULL);

    if (current_time.tv_sec - start_time->tv_sec >= 5)
        return true;
    return false;
}

int recieve_packet(char *filter_exp)
{
    char                errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t           *alldevs;
    pcap_if_t           *dev;
    struct pcap_pkthdr  *header;
	const u_char        *packet;
    pcap_t              *handle;
    struct bpf_program  fp;
    bpf_u_int32         net = 0;
    bpf_u_int32         mask = 0;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }
    
    if (alldevs == NULL) {
        fprintf(stderr, "No devices found\n");
        return -1;
    }
    
    dev = alldevs;
    if (dev->name == NULL) {
        fprintf(stderr, "First device has no name\n");
        return -1;
    }

    handle = pcap_open_live(dev->name, 65535, 1, 100, errbuf);

    if (pcap_setnonblock(handle, 1, errbuf) == -1) {
        fprintf(stderr, "Error setting non-blocking mode: %s\n", errbuf);
        return -1;
    }

    pcap_freealldevs(alldevs);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev->name, errbuf);
        return -1;
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -1;
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return -1;
	}

    struct timeval start_time;
    gettimeofday(&start_time, NULL);
    while (!check_time_out(&start_time))
    {
        int result = pcap_next_ex(handle, &header, &packet);
        if (result == 1)
        {
            const char  *ip_header = packet + 14;
            struct ip   *iph = (struct ip *)ip_header;
            int ip_header_len = iph->ip_hl * 4;

            // ACK or RST Response
            if (iph->ip_p == IPPROTO_TCP)
            {
                const char      *tcp_header = ip_header + ip_header_len;
                struct tcphdr   *tcph = (struct tcphdr *)tcp_header;
                if (tcph->ack == 1)
                    return OPEN;
                return CLOSED;
            }
            // ICMP Errors Response
            else if (iph->ip_p == IPPROTO_ICMP)
            {
                const char *icmp_header = ip_header + ip_header_len;
                struct icmphdr *icmphdr = (struct icmphdr *)icmp_header;
                if (icmphdr->type == ICMP_UNREACH)
                {
                    if (icmphdr->code == 1 || icmphdr->code == 2 || icmphdr->code == 3 || icmphdr->code == 9 || icmphdr->code == 10 || icmphdr->code ==  13)
                    {
                        return FILTERED;
                    }
                }
            }
            // No Response
            return FILTERED;
            // printf("soure Port: %d\n", ntohs(tcph->th_sport));
            // printf("Destination Port: %d\n", ntohs(tcph->th_dport));
        }
        usleep(1000);
    }
    pcap_close(handle);
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
    tsock = get_target_address("8.8.8.8", 116);
    int value = 1;

    setsockopt(tcp_socket, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value));

    generate_ip_header(probe, source_address.sin_addr, tsock.socket.sin_addr);
    generate_tcp_header(116, TH_SYN, probe, source_address.sin_addr, tsock.socket.sin_addr);

    memcpy(data, &probe->ip_header, sizeof(struct ip));
    memcpy(data + sizeof(struct ip), &probe->tcp_header, sizeof(struct tcphdr));

    int send_res = sendto(tcp_socket, (void *)data, sizeof(struct ip) + sizeof(struct tcphdr), 0,(struct sockaddr *)&tsock.socket, tsock.socket_len);
    if (send_res < 0)
    {
        print_error("sendto error: %s", strerror(send_res));
        exit(1);
    }
    // char filter_exp[] = "src host 18.154.84.103 and src port 443";
    int response = recieve_packet("src host 8.8.8.8 and src port 116");
    printf("RES: %d\n", response);

    switch (response)
    {
    case OPEN:
        printf("Port Open\n");
        break;
    case CLOSED:
        printf("Port Closed\n");
        break;
    default:
        printf("Port Closed 2\n");
        break;
    }
}