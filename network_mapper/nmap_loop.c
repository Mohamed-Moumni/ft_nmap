#include "../ft_nmap.h"

void nmap_loop(t_input *nmap_input)
{
    t_list	*nmap;
	t_nmap	*nmap_node;
	t_list	*nmap_list_node;
	t_list	*threads;
	t_list	*next_port_head;
	int		offset;
	int		step_count;
	int		remainder;

	nmap = NULL;
	offset = 0;
	remainder = 0;
	step_count = nmap_input->port_count <= nmap_input->thread_count ? 1 : nmap_input->port_count / nmap_input->thread_count;
	if (nmap_input->port_count <= nmap_input->thread_count)
		nmap_input->thread_count = nmap_input->port_count;
	if (nmap_input->port_count > nmap_input->thread_count)
		remainder = nmap_input->port_count % nmap_input->thread_count;

    while(nmap_input->ipaddr)
	{
		if (nmap_input->ipaddr->discovery)
		{
			threads = NULL;
			nmap_node = create_nmap_node(nmap_input->ipaddr);
			print_stats(nmap_node->ipaddr->ip_addr, nmap_input->port_count, nmap_input->scans, nmap_input->thread_count);
			nmap_list_node = list_new(nmap_node, sizeof(t_list));
			// iterate through the threads
			for (int i = 0; i < nmap_input->thread_count; i++)
			{
				pthread_t *thread;

				thread = malloc(sizeof(pthread_t));
				t_list	*thread_node = list_new(thread, sizeof(pthread_t));
				list_add(&threads, thread_node);
				t_routine_arg *routine_arg;

				routine_arg = malloc(sizeof(t_routine_arg));
				next_port_head = next_head_ports(nmap_input->ports, offset);
				routine_arg->nmap = (t_nmap *)nmap_list_node->data;
				routine_arg->port_range = step_count + remainder;
				routine_arg->scans = nmap_input->scans;
				routine_arg->ports = next_port_head;
				routine_arg->nmap->closed_ports = NULL;
				routine_arg->nmap->open_ports = NULL;

				// create the thread
				int error = pthread_create(((pthread_t *)thread_node->data), NULL, thread_routine, routine_arg);
				if (error != 0)
					print_error("Pthread Create: %s\n", strerror(error));
				remainder = remainder > 0 ? 0 : remainder;
				offset += step_count;
				free(thread);
			}
			join_threads(threads, (t_nmap **)&nmap_list_node->data);
			list_free(&threads);
			free(nmap_node);
			// sorting output
			list_add(&nmap, nmap_list_node);
		}
		nmap_input->ipaddr = nmap_input->ipaddr->next;
	}
}