#include "../ft_nmap.h"

void	error_print(char *error_msg)
{
    printf("%s\n", error_msg);
}

t_list *list_new(void *data, size_t data_size)
{
    t_list *new_item = malloc(sizeof(t_list));
    if (!new_item)
    {
        error_print("Memory allocation error: New List Item can't be allocated");
        exit(1);
    }
    void *data = malloc(sizeof(data_size));
    if (!data)
    {
        error_print("Memory allocation error: New Data Item can't be allocated");
        exit(1);
    }
    new_item->data = data;
    new_item->next = NULL;
    return new_item;
}

void list_add(t_list **list, t_list *new_item)
{
    t_list *temp_item;

    if ((*list) == NULL)
        (*list) = new_item;
    else
    {
        temp_item = (*list);
        while (temp_item->next)
        {
            temp_item = temp_item->next;
        }
        temp_item = new_item;
    }
}

t_scan  *create_scan(int type)
{
    t_scan *scan = malloc(sizeof(t_scan));
    if (!scan)
    {
        error_print("Memory Allocation error: New Scan Item can't be allocated");
        exit(1);
    }
    scan->type = type;
    return scan;
}

t_port  *create_port(int port_nb)
{
    t_port *port = malloc(sizeof(t_port));
    if (!port)
    {
        error_print("Memory Allocation error: New Port Item can't be allocated");
        exit(1);
    }
    port->port_number = port_nb;
    return port;
}

t_nmap  *create_nmap_node(t_ipaddr *ipaddr)
{
    t_nmap *nmap = malloc(sizeof(t_nmap));
    if (!nmap)
    {
        error_print("Memory Allocation error: New Nmap Item can't be allocated");
        exit(1);
    }
    nmap->ipaddr = ipaddr;
    return nmap;
}

// char *tcp_header(int tcp_byte)
// {
    // struct tcphdr *tcp_header;
// 
// }