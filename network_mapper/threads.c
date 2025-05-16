#include "../ft_nmap.h"

void	join_threads(t_list *threads, t_nmap **nmap_list)
{
    t_list          *thread_temp;
    t_thread_res    *thread_result;
    
    thread_temp = threads;
    while(thread_temp)
    {
        pthread_t       thread;
        
        thread = *((pthread_t *)thread_temp->data);
        int res = pthread_join(thread, (void *)&thread_result);
        if (res)
            print_error("Join Threads: %s \n", strerror(res));
        port_add(&(*nmap_list)->closed_ports, thread_result->closed_ports);
        port_add(&(*nmap_list)->open_ports, thread_result->open_ports);
        thread_temp = thread_temp->next;
    }
}

void    *thread_routine(void* arg)
{     
    t_routine_arg   *routine_arg;
    int             send_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    int             value;
    char            *filter;
    bool            is_open;
    t_thread_res    *thread_result;

    value = 1;    
    if (send_socket == -1)
        print_error("Socket Creation Error\n");
    setsockopt(send_socket, IPPROTO_IP, IP_HDRINCL, &value, sizeof(value));

    routine_arg = (t_routine_arg *)arg;

    thread_result = malloc(sizeof(t_thread_res));
    if (!thread_result)
        print_error("Malloc Error: Thread Result");
    thread_result->open_ports = NULL;
    thread_result->closed_ports = NULL;
    
    // starting the process of port scanning
    // for each port the available scan will be performed
    while (routine_arg->ports && routine_arg->port_range > 0)
    {
        int     port = *((int *)routine_arg->ports->data);
        t_port  *port_node = create_port(port);
        t_scan  *scans = NULL;
        t_list  *scans_temp = routine_arg->scans;
        is_open = false;

        while (scans_temp)
        {
            int     scan = *((int *)scans_temp->data);
            t_scan  *scan_node = create_scan(scan);
            switch (scan)
            {
                case UDP_SCAN:
                    scan_node->state = udp_scan(routine_arg->nmap->ipaddr->ip_addr, port);
                    is_open = scan_node->state != OPEN ? false : true;
                    break;
                case NULL_SCAN:
                    scan_node->state = tcp_scan(routine_arg->nmap->ipaddr->ip_addr, 0, port, send_socket, NULL_SCAN);
                    is_open = scan_node->state != OPEN ? false : true;
                    break;
                case ACK_SCAN:
                    scan_node->state = tcp_scan(routine_arg->nmap->ipaddr->ip_addr, TH_ACK, port, send_socket, ACK_SCAN);
                    is_open = scan_node->state != OPEN ? false : true;
                    break;
                case XMAS_SCAN:
                    scan_node->state = tcp_scan(routine_arg->nmap->ipaddr->ip_addr, TH_FIN | TH_PUSH | TH_URG, port, send_socket, XMAS_SCAN);
                    is_open = scan_node->state != OPEN ? false : true;
                    break;
                case FIN_SCAN:
                    scan_node->state = tcp_scan(routine_arg->nmap->ipaddr->ip_addr, TH_FIN, port, send_socket, FIN_SCAN);
                    is_open = scan_node->state != OPEN ? false : true;
                    break;
                case SYN_SCAN:
                    scan_node->state = tcp_scan(routine_arg->nmap->ipaddr->ip_addr, TH_SYN, port, send_socket, SYN_SCAN);
                    is_open = scan_node->state != OPEN ? false : true;
                    break;
                default:
                    break;
            }
            scan_add(&scans, scan_node);
            scans_temp = scans_temp->next;
        }
        port_node->scans = scans;
        port_node->category = get_scan_conclusion(scans);
        if (is_open)
            port_add(&thread_result->open_ports, port_node);
        else
            port_add(&thread_result->closed_ports, port_node);
        routine_arg->ports = routine_arg->ports->next;
        routine_arg->port_range--;
    }
    close(send_socket);
    return thread_result;
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