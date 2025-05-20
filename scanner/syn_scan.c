#include "../ft_nmap.h"

bool check_time_out(struct timeval *start_time)
{
    struct timeval  current_time;

    gettimeofday(&current_time, NULL);
    if (current_time.tv_sec - start_time->tv_sec >= 4)
        return true;
    return false;
}

const u_char *packet_receive(pcap_t  *handle)
{
    struct pcap_pkthdr  *header;
    const u_char        *packet = NULL;
    struct timeval      start_time;


    gettimeofday(&start_time, NULL);
    int result;
    while (!check_time_out(&start_time))
    {
        result = pcap_next_ex(handle, &header, &packet);
        if (result == 1)
            return packet;
        else if (result == -1)
            print_error("Error reading packet: %s\n", pcap_geterr(handle));
    }
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

void generate_ip_header(struct ip *ip_header, struct in_addr *ip_source, struct in_addr *ip_destination, int protocol)
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
    ip_header->ip_src = *ip_source;
    ip_header->ip_dst = *ip_destination;
    ip_header->ip_sum = checksum((void *)ip_header, sizeof(struct ip));
}

void generate_tcp_header(struct tcphdr *tcp_header, struct in_addr *ip_source, struct in_addr *ip_destination, int port, int scan_type)
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

    pseudo_header.source_address = ip_source->s_addr;
    pseudo_header.dest_address = ip_destination->s_addr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(sizeof(struct tcphdr));

    memcpy(buf, &pseudo_header, sizeof(t_pseudo_header));
    memcpy(buf + sizeof(t_pseudo_header), tcp_header, sizeof(struct tcphdr));

    tcp_header->th_sum = checksum(buf, sizeof(t_pseudo_header) + sizeof(struct tcphdr));
}

void send_tcp_packet(t_socket *src_addr, t_socket *dest_addr, const int send_socket, const int port, const int tcp_flag)
{
    char                data[1024] = {0};
	struct ip		    ip_header;
    struct tcphdr       tcp_header;

    generate_ip_header(&ip_header, &src_addr->sock_addr->sin_addr, &dest_addr->sock_addr->sin_addr, IPPROTO_TCP);
    generate_tcp_header(&tcp_header, &src_addr->sock_addr->sin_addr, &dest_addr->sock_addr->sin_addr, port, tcp_flag);
    memcpy(data, &ip_header, sizeof(struct ip));
    memcpy(data + sizeof(struct ip), &tcp_header, sizeof(struct tcphdr));

    int send_res = sendto(send_socket, data, sizeof(struct ip) + sizeof(struct tcphdr), 0, dest_addr->sock_addr, dest_addr->sock_len);
    if (send_res < 0)
        print_error("sendto error: %s", strerror(send_res));
}

int tcp_scan(t_socket *src_addr, t_socket *dest_addr, const char *filter, int tcp_flag, int port, int socket, int scan_type, pcap_t *handle)
{
    const u_char    *packet;
    int             scan_res;
    struct bpf_program  fp;
    bpf_u_int32         net = 0;

    Timer t;
    timer_start(&t);
    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    print_error("Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
    if (pcap_setfilter(handle, &fp) == -1)
    print_error("Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
    timer_stop(&t);
    timer_print_elapsed(&t, "seting filter", port);
    
    printf("\n");

    timer_start(&t);
    send_tcp_packet(src_addr, dest_addr, socket, port, tcp_flag);
    timer_stop(&t);
    timer_print_elapsed(&t, "sending packet", port);

    printf("\n");

    timer_start(&t);
    packet = packet_receive(handle);
    timer_stop(&t);
    timer_print_elapsed(&t, "receiving packet", port);
    scan_res = handle_packet(packet, scan_type);
    return scan_res;
}

void set_conclusion(int *max_state_occur, int *conclusion, int *state_counter, const int scan_state)
{
    if ((*state_counter) > (*max_state_occur))
    {
        (*max_state_occur) = (*state_counter);
        *conclusion = scan_state;
    }
}

void update_conclusion(int *state_counter, int *conclusion, int max_count)
{
    if (state_counter[4] == max_count)
        *conclusion = OPEN_FILTERED;
    if (state_counter[3] == max_count)
        *conclusion = UNFILTERED;
    if (state_counter[2] == max_count)
        *conclusion = FILTERED;
    if (state_counter[1] == max_count)
        *conclusion = CLOSED;
    if (state_counter[0] == max_count)
        *conclusion = OPEN;
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
            set_conclusion(&max_state_occur, &conclusion, &state_counter[0], OPEN);
            break;
        case CLOSED:
            state_counter[1]++;
            set_conclusion(&max_state_occur, &conclusion, &state_counter[1], CLOSED);
            break;
        case FILTERED:
            state_counter[2]++;
            set_conclusion(&max_state_occur, &conclusion, &state_counter[2], FILTERED);
            break;
        case UNFILTERED:
            set_conclusion(&max_state_occur, &conclusion, &state_counter[3], UNFILTERED);
            state_counter[3]++;
            break;
        case OPEN_FILTERED:
            set_conclusion(&max_state_occur, &conclusion, &state_counter[4], OPEN_FILTERED);
            state_counter[4]++;
            break;
        default:
            break;
        }
        scans = scans->next;
    }
    update_conclusion(state_counter, &conclusion, max_state_occur);
    return conclusion;
}