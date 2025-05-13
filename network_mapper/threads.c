#include "../ft_nmap.h"

void* thread_routine(void* arg)
{     
    t_routine_arg   *routine_arg;
    int             send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    int             value;
    char            *filter;

    value = 1;    
    if (send_socket == -1)
        print_error("Socket Creation Error\n");
    setsockopt(send_socket, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value));

    routine_arg = (t_routine_arg *)arg;
    printf("Thread Routine Method!!\n");
    printf("Port Range: %d\n", routine_arg->port_range);
    // starting the process of port scanning for the start to the end
    // for each port do the available scan that should performed
    while (routine_arg->ports && routine_arg->port_range > 0)
    {
        int port = *((int *)routine_arg->ports->data);
        printf("Port number: %d\n", port);
        while (routine_arg->scans)
        {
            int scan = *((int *)routine_arg->scans->data);
            switch (scan)
            {
                case UDP_SCAN:
                    int res = udp_scan(routine_arg->nmap->ipaddr->ip_addr, port);
                    printf("Result --- %d\n", res);
                    break;
                case NULL_SCAN:
                    int res2 = tcp_scan(routine_arg->nmap->ipaddr->ip_addr, 0, port, send_socket, NULL_SCAN);
                    printf("Result -- %d\n", res2);
                    break;
                case ACK_SCAN:
                    int res3 = tcp_scan(routine_arg->nmap->ipaddr->ip_addr, TH_ACK, port, send_socket, ACK_SCAN);
                    printf("Result -- %d\n", res3);
                    break;
                case XMAS_SCAN:
                    int res4 = tcp_scan(routine_arg->nmap->ipaddr->ip_addr, TH_FIN | TH_PUSH | TH_URG, port, send_socket, XMAS_SCAN);
                    printf("Result -- %d\n", res4);
                    break;
                case FIN_SCAN:
                    int res5 = tcp_scan(routine_arg->nmap->ipaddr->ip_addr, TH_FIN, port, send_socket, FIN_SCAN);
                    printf("Result -- %d\n", res5);
                    break;
                case SYN_SCAN:
                    int res6 = tcp_scan(routine_arg->nmap->ipaddr->ip_addr, TH_SYN, port, send_socket, SYN_SCAN);
                    printf("Result -- %d\n", res6);
                    break;
                default:
                    break;
            }
            routine_arg->scans = routine_arg->scans->next;
        }
        routine_arg->ports = routine_arg->ports->next;
        routine_arg->port_range--;
    }
    return "hello";
}

t_list	*next_head_ports(t_list *ports, int offset)
{
    t_list *port_temp;

    port_temp = ports;
    while (port_temp && offset > 0)
    {
        offset--;
        port_temp = port_temp->next;
    }
    return port_temp;
}