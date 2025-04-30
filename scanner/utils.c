#include "../ft_nmap.h"

void print_error(const char *format, ...)
{
    va_list args;
    fprintf(stderr, "ft_traceroute - error: ");

    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    fprintf(stderr, "\n");
    exit(EXIT_FAILURE);
}

t_list  *list_new(void *data, size_t data_size)
{
    t_list *new_item = malloc(sizeof(t_list));
    if (!new_item)
    {
        print_error("Memory Allocation error: New List Item can't be allocated");
        exit(1);
    }
    new_item->data = malloc(data_size);
    if (!new_item->data)
    {
        print_error("Memory allocation error: New Data Item can't be allocated");
        exit(1);
    }
    memcpy(new_item->data, data, data_size);
    new_item->next = NULL;
    return new_item;
}

int node_counter(t_list *data)
{
    int to_return = 0;
    while (data)
    {
        to_return++;
        data = data->next;
    }
    return to_return;
}

void    list_add(t_list **list, t_list *new_item)
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
        temp_item->next = new_item;
    }
}

void    list_free(t_list **list_item)
{
    t_list *list_temp;
    t_list *list_item_to_free;

    list_temp = *list_item;
    while (list_temp)
    {
        list_item_to_free = list_temp;
        list_temp = list_temp->next;
        free(list_item_to_free);
    }
}

t_scan  *create_scan(int type)
{
    t_scan *scan = malloc(sizeof(t_scan));
    if (!scan)
    {
        print_error("Memory Allocation error: Scan Item Can't Be allocated");
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
        print_error("Memory Allocation error: Port Item Can't Be allocated");
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
        print_error("Memory Allocation error: Nmpa Item Can't Be allocated");
        exit(1);
    }
    nmap->ipaddr = ipaddr;
    return nmap;
}
