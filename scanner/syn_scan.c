#include "../ft_nmap.h"

void generate_ip_header(struct ip *ip_header, struct in_addr ip_source, struct in_addr ip_destination, int protocol)
{
    ip_header->ip_v = 4;
    ip_header->ip_hl = 5;
    ip_header->ip_tos = 0;
    if (protocol == IPPROTO_TCP)
        ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    else
        ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct udphdr));
    ip_header->ip_id = htons(generate_random_id());
    ip_header->ip_off = htons(0);
    ip_header->ip_ttl = TTL;
    ip_header->ip_p = protocol;
    ip_header->ip_sum = 0;
    ip_header->ip_src = ip_source;
    ip_header->ip_dst = ip_destination;
    ip_header->ip_sum = checksum((void *)ip_header, sizeof(struct ip));
}

void generate_tcp_header(struct tcphdr *tcp_header, struct in_addr ip_source, struct in_addr ip_destination, int port, int scan_type)
{
    t_pseudo_header pseudo_header;
    char            buf[1024] = {0};

    tcp_header->th_sport = htons(generate_random_id());
    tcp_header->th_dport = htons(port);
    tcp_header->th_seq = htonl(0);
    tcp_header->th_ack = 0;
    tcp_header->th_off = 5;
    tcp_header->th_flags = scan_type;
    tcp_header->th_win = htons(65535);
    tcp_header->th_sum = 0;
    tcp_header->th_urp = 0;

    pseudo_header.source_address = ip_source.s_addr;
    pseudo_header.dest_address = ip_destination.s_addr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(sizeof(struct tcphdr));

    memcpy(buf, &pseudo_header, sizeof(t_pseudo_header));
    memcpy(buf + sizeof(t_pseudo_header), tcp_header, sizeof(struct tcphdr));

    tcp_header->th_sum = checksum(buf, sizeof(t_pseudo_header) + sizeof(struct tcphdr));
}

bool check_time_out(struct timeval *start_time)
{
    struct timeval  current_time;

    gettimeofday(&current_time, NULL);
    if (current_time.tv_sec - start_time->tv_sec >= 4)
        return true;
    return false;
}

const u_char *packet_receive(const char *filter_exp)
{
    char                errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t           *alldevs;
    pcap_if_t           *dev;
    struct pcap_pkthdr  *header;
    const u_char        *packet = NULL;
    pcap_t              *handle;
    struct bpf_program  fp;
    struct timeval      start_time;
    bpf_u_int32         net = 0;

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        print_error("Error finding devices: %s\n", errbuf);

    if (alldevs == NULL)
        print_error("No devices found\n");

    dev = alldevs;
    if (dev->name == NULL)
        print_error("First device has no name\n");

    handle = pcap_open_live(dev->name, 65535, 1, 100, errbuf);

    if (pcap_setnonblock(handle, 1, errbuf) == -1)
        print_error("Error setting non-blocking mode: %s\n", errbuf);

    pcap_freealldevs(alldevs);
    if (handle == NULL)
        print_error("Couldn't open device %s: %s\n", dev->name, errbuf);
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
        print_error("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    if (pcap_setfilter(handle, &fp) == -1)
        print_error("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));

    gettimeofday(&start_time, NULL);
    while (!check_time_out(&start_time))
    {
        int result = pcap_next_ex(handle, &header, &packet);
        if (result == 1)
            return packet;
        usleep(1000);
    }
    pcap_close(handle);
    return NULL;
}

int handle_packet(const u_char *packet, int scan)
{
    switch (scan)
    {
    case SYN_SCAN:
        return syn_handler(packet);
    case ACK_SCAN:
        return ack_handler(packet);
    case NULL_SCAN:
        return FNX_handler(packet);
    case XMAS_SCAN:
        return FNX_handler(packet);
    case FIN_SCAN:
        return FNX_handler(packet);
    case UDP_SCAN:
        return udp_handler(packet);
    default:
        return -1;
    }
}


void send_tcp_packet(t_socket *src_addr, t_socket *dest_addr, const int send_socket, const int port, const int tcp_flag)
{
    char                data[1024] = {0};
	struct ip		    ip_header;
    struct tcphdr       tcp_header;

    generate_ip_header(&ip_header, src_addr->sock_addr.sin_addr, dest_addr->sock_addr.sin_addr, IPPROTO_TCP);
    generate_tcp_header(&tcp_header, src_addr->sock_addr.sin_addr, dest_addr->sock_addr.sin_addr, port, tcp_flag);

    memcpy(data, &ip_header, sizeof(struct ip));
    memcpy(data + sizeof(struct ip), &tcp_header, sizeof(struct tcphdr));

    int send_res = sendto(send_socket, (void *)data, sizeof(struct ip) + sizeof(struct tcphdr), 0, &dest_addr->sock_addr, dest_addr->sock_len);
    if (send_res < 0)
        print_error("sendto error: %s", strerror(send_res));
}

int tcp_scan(t_socket *src_addr, t_socket *dest_addr, const char *filter, int tcp_flag, int port, int socket, int scan_type)
{
    const u_char    *packet;
    int             scan_res;

    send_tcp_packet(src_addr, dest_addr, socket, port, tcp_flag);
    packet = packet_receive(filter);
    scan_res = handle_packet(packet, scan_type);
    return scan_res;
}

void update_conculsion(int *max_state_occur, int *conclusion, int *state_counter, const int scan_state)
{
    if ((*state_counter) > (*max_state_occur))
    {
        (*max_state_occur) = (*state_counter);
        *conclusion = scan_state;
    }
}

int get_scan_conclusion(t_scan *scans)
{
    // open | closed | filtered | unfiltered | open_filtered
    int state_counter[5] = {0};
    int max_state_occur = 0;
    int conclusion = OPEN;

    while (scans)
    {
        switch (scans->state)
        {
        case OPEN:
            state_counter[0]++;
            update_conculsion(&max_state_occur, &conclusion, &state_counter[0], OPEN);
            break;
        case CLOSED:
            state_counter[1]++;
            update_conculsion(&max_state_occur, &conclusion, &state_counter[1], CLOSED);
            break;
        case FILTERED:
            state_counter[2]++;
            update_conculsion(&max_state_occur, &conclusion, &state_counter[2], FILTERED);
            break;
        case UNFILTERED:
            update_conculsion(&max_state_occur, &conclusion, &state_counter[3], UNFILTERED);
            state_counter[3]++;
            break;
        case OPEN_FILTERED:
            update_conculsion(&max_state_occur, &conclusion, &state_counter[4], OPEN_FILTERED);
            state_counter[4]++;
            break;
        default:
            break;
        }
        scans = scans->next;
    }
    return conclusion;
}