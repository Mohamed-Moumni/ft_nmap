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
        while (routine_arg->scans)
        {
            int scan = *((int *)routine_arg->scans->data);
            switch (scan)
            {
                case UDP_SCAN:
                    int res = udp_scan(routine_arg->nmap->ipaddr->ip_addr, port);
                    printf("Result --- %d\n", res);
                    break;
                default:
                    int res2 = tcp_scan(routine_arg->nmap->ipaddr->ip_addr, scan, port, send_socket);
                    printf("Result -- %d\n", res2);
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