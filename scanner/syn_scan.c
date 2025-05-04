#include "../ft_nmap.h"

// Get TCP Header

// Get IP Header

t_scan  *syn_scan(int port_number, int socket, struct sockaddr_in *sockaddr, socklen_t socklen)
{
    // in this method i have to perform the SYN scan on this port number
    // for this ip address.
    // waiting for a response from the target.

    char    data[1024];
    t_probe *probe;

    memset(data, 1024, 0);
    srand(time(NULL));

    probe = (t_probe *)data;
    probe->ip_header.version = htonl(4);
    probe->ip_header.ihl = htons(5);
    probe->ip_header.tos = htons(0);
    probe->ip_header.tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    probe->ip_header.frag_off = htons(0);
    probe->ip_header.id = htons(rand() % 65536);
    probe->ip_header.ttl = htons(128);
    probe->ip_header.protocol = IPPROTO_TCP;
    probe->ip_header.check = htons(0);
    probe->ip_header.saddr = 0;
    probe->ip_header.daddr = 0;

    probe->ip_header.check = checksum((void *)(&probe->ip_header), sizeof(struct iphdr));

    // TCP Header

    // probe->tcp_header.

    probe->tcp_header.th_sport = htons(54321);
    probe->tcp_header.th_dport = htons(port_number);
    probe->tcp_header.seq = htons(rand() % 65536);
    probe->tcp_header.ack = htons(0);
    probe->tcp_header.th_flags = TH_SYN;
    probe->tcp_header.doff = htons(5);
    probe->tcp_header.check = htons(0);
    probe->tcp_header.urg_ptr = htons(0);
    probe->tcp_header.window = htons(5840);
    probe->tcp_header.check = checksum((void *)(&probe->tcp_header), sizeof(struct tcphdr));

    int send = sendto(socket, data, sizeof(t_probe), 0, sockaddr, socklen);
    if (send < 0)
    {
        printf("Send To Error: \n", strerror(send));
        exit(1);
    }
}


struct sockaddr_in get_local_address(void)
{
    int                 sock;
    struct sockaddr_in  local_addr;
    socklen_t addr_len = sizeof(local_addr);
    char src_ip[INET_ADDRSTRLEN];

    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
    {
        printf("Socket Error: \n");
        exit(1);
    }
    getsockname(sock, (struct sockaddr *)&local_addr, &addr_len);
    return local_addr;
}

struct sockaddr_in get_target_address(void)
{
    int     sock;
    struct sockaddr_in  dest_addr;
    socklen_t addr_len = sizeof(dest_addr);

    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dest_addr.sin_addr);
    return dest_addr;
}

int main(void)
{
    // int tcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    // if (tcp_socket == -1)
    // {
        // printf("Socket Creation Error\n");
        // exit(1);
    // }
    
    // struct tcphdr tcp_header;

    // tcp_header.th_flags = TH_SYN;

    // tcp_header.

    get_local_address();
}