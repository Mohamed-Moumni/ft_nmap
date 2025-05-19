#include "../ft_nmap.h"

void generate_udp_header(struct udphdr *udp_header, struct in_addr ip_source, struct in_addr ip_destination, int port)
{
    t_pseudo_header pseudo_header;
    char buf[1024] = {0};
    
    // Fill in UDP header fields
    udp_header->uh_sport = htons(generate_random_id());
    udp_header->uh_dport = htons(port);
    udp_header->uh_ulen = htons(sizeof(struct udphdr));
    udp_header->uh_sum = 0;

    pseudo_header.source_address = ip_source.s_addr;
    pseudo_header.dest_address = ip_destination.s_addr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_UDP;  // UDP protocol
    pseudo_header.tcp_length = htons(sizeof(struct udphdr));
    
    memcpy(buf, &pseudo_header, sizeof(t_pseudo_header));
    memcpy(buf + sizeof(t_pseudo_header), udp_header, sizeof(struct udphdr));
    
    udp_header->uh_sum = checksum(buf, sizeof(t_pseudo_header) + sizeof(struct udphdr));
}

int udp_handler(const u_char *packet)
{
    if (packet)
    {
        const char *ip_header = (char *)packet + 14;
        struct ip *iph = (struct ip *)ip_header;
        int ip_header_len = iph->ip_hl * 4;
        
        if (iph->ip_p == IPPROTO_UDP)
			return OPEN;
        else if (iph->ip_p == IPPROTO_ICMP)
        {
            const char *icmp_header = ip_header + ip_header_len;
            struct icmphdr *icmphdr = (struct icmphdr *)icmp_header;
            
            if (icmphdr->type == ICMP_UNREACH)
            {
                if (icmphdr->code == 3)
                {
                    return CLOSED;
                }
                else if (icmphdr->code == 1 || icmphdr->code == 2 || 
                         icmphdr->code == 9 || icmphdr->code == 10 || 
                         icmphdr->code == 13)
                {
                    return FILTERED;
                }
            }
        }
    }
    return OPEN_FILTERED;
}

void	send_udp_packet(t_socket *src_addr, t_socket *dest_addr, const int send_socket, const int port)
{
	char                data[1024] = {0};
	struct ip		    ip_header;
    struct udphdr       udp_header;


    generate_ip_header(&ip_header, &src_addr->sock_addr->sin_addr, &dest_addr->sock_addr->sin_addr, IPPROTO_UDP);
    generate_udp_header(&udp_header, src_addr->sock_addr->sin_addr, dest_addr->sock_addr->sin_addr, port);

    memcpy(data, &ip_header, sizeof(struct ip));
    memcpy(data + sizeof(struct ip), &udp_header, sizeof(struct udphdr));

    int send_res = sendto(send_socket, (void *)data, sizeof(struct ip) + sizeof(struct udphdr), 0, dest_addr->sock_addr, dest_addr->sock_len);
    if (send_res < 0)
        print_error("sendto error: %s", strerror(send_res));
}

int		udp_scan(t_socket *src_addr, t_socket *dest_addr, const char *filter, int port, int socket, int scan_type, pcap_t *handle)
{
    const u_char    *packet;
    int             scan_res;
    struct bpf_program  fp;
    bpf_u_int32         net = 0;

    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
        print_error("Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
    if (pcap_setfilter(handle, &fp) == -1)
        print_error("Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));

    send_udp_packet(src_addr, dest_addr, socket, port);
    packet = packet_receive(handle);
    scan_res = handle_packet(packet, scan_type);
    return scan_res;
}
