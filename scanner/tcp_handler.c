#include "../ft_nmap.h"

int ack_handler(const u_char *packet)
{
    if (packet)
    {
        const char  *ip_header = packet + 14;
        struct ip   *iph = (struct ip *)ip_header;
        int         ip_header_len = iph->ip_hl * 4;
    
        // ACK or RST Response
        if (iph->ip_p == IPPROTO_TCP)
        {
            const char      *tcp_header = ip_header + ip_header_len;
            struct tcphdr   *tcph = (struct tcphdr *)tcp_header;
            if (tcph->rst == 1)
                return UNFILTERED;
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
    }
    return FILTERED;
}

int syn_handler(const u_char *packet)
{
    if (packet)
    {
        printf("Syn handler\n");
        const char  *ip_header = packet + 14;
        struct ip   *iph = (struct ip *)ip_header;
        int         ip_header_len = iph->ip_hl * 4;
    
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
    }
    return FILTERED;
}

int FNX_handler(const u_char *packet)
{
    if (packet)
    {
        const char  *ip_header = packet + 14;
        struct ip   *iph = (struct ip *)ip_header;
        int         ip_header_len = iph->ip_hl * 4;
    
        // ACK or RST Response
        if (iph->ip_p == IPPROTO_TCP)
        {
            const char      *tcp_header = ip_header + ip_header_len;
            struct tcphdr   *tcph = (struct tcphdr *)tcp_header;
            if (tcph->rst == 1)
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
    }
    return OPEN_FILTERED;
}