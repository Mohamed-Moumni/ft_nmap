#include "../ft_nmap.h"

void    node_init(t_ipaddr **list, char *ipaddr, struct sockaddr *sockaddr, socklen_t addrlen)
{
	*list = malloc(sizeof(t_ipaddr));
	(*list)->ip_addr = ipaddr;
    (*list)->sock_addr = sockaddr;
	(*list)->addr_len = addrlen;
	(*list)->next = NULL;
}

int	add_node(t_ipaddr **list, char *ipaddr, struct sockaddr *sockaddr, socklen_t addrlen)
{
	t_ipaddr	*tmp;
	t_ipaddr	*new_node;

	if (!(*list))
		node_init(list, ipaddr, sockaddr, addrlen);
	else
	{	
		tmp = *list;
		node_init(&new_node, ipaddr, sockaddr, addrlen);
		while (tmp->next)
			tmp = tmp->next;
		tmp->next = new_node;
	}
	return 0;
}
