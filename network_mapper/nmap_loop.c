#include "../ft_nmap.h"

void counters_setting(int *thread_count, int *port_count, int *step_count, int *remainder)
{
	*remainder = 0;
	*step_count = *port_count <= *thread_count ? 1 : *port_count / *thread_count;

	if (*port_count <= *thread_count)
		*thread_count = *port_count;
	if (*port_count > *thread_count)
		*remainder = *port_count % *thread_count;
}

void nmap_loop(t_input *nmap_input)
{
    t_list			*nmap;
	t_nmap			*nmap_node;
	t_list			*nmap_list_node;
	t_list			*threads;
	t_socket		*src_addr;
	t_socket		*dest_addr;
	int				offset;
	int				step_count;
	int				remainder;
	int				scan_counter;
	struct timeval	sending_time;

	nmap = NULL;
	scan_counter = node_counter(nmap_input->scans);
	src_addr = get_local_addr();

    while(nmap_input->ipaddr)
	{
		dest_addr = malloc(sizeof(struct sockaddr_in));
		if (!dest_addr)
			print_error("Destination Address Malloc Error");
		dest_addr->sock_addr = (struct sockaddr_in *)nmap_input->ipaddr->sock_addr;
		dest_addr->sock_len = nmap_input->ipaddr->addr_len;
		if (nmap_input->ipaddr->discovery)
		{
			threads = NULL;
			offset = 0;
			nmap_node = create_nmap_node(nmap_input->ipaddr);
			nmap_list_node = list_new(nmap_node, sizeof(t_list));
			if (nmap_input->thread_count)
				counters_setting(&nmap_input->thread_count, &nmap_input->port_count, &step_count, &remainder);

			print_stats(nmap_node->ipaddr->ip_addr, nmap_input->port_count, nmap_input->scans, nmap_input->thread_count);

			t_routine_arg *routine_arg;
			if (gettimeofday(&sending_time, NULL) != 0)
				print_error("Get Time of Day Error");
			if (!nmap_input->thread_count)
			{
				// main thread (main Process)
				routine_arg = malloc(sizeof(t_routine_arg));
				routine_arg->nmap = (t_nmap *)nmap_list_node->data;
				routine_arg->scans = nmap_input->scans;
				routine_arg->src_addr = src_addr;
				routine_arg->dest_addr = dest_addr;
				routine_arg->nmap->closed_ports = NULL;
				routine_arg->nmap->open_ports = NULL;
				routine_arg->port_range = nmap_input->port_count;
				routine_arg->ports = nmap_input->ports;

				t_thread_res	*thread_result = thread_routine(routine_arg);
				t_nmap			*nmap_list;
				
				nmap_list = (t_nmap *)nmap_list_node->data;
				port_add(&nmap_list->closed_ports, thread_result->closed_ports);
				port_add(&nmap_list->open_ports, thread_result->open_ports);
				free(routine_arg);
			}
			else
			{
				// iterate through the threads
				for (int i = 0; i < nmap_input->thread_count; i++)
				{
					pthread_t *thread;

					thread = malloc(sizeof(pthread_t));
					t_list	*thread_node = list_new(thread, sizeof(pthread_t));
					list_add(&threads, thread_node);

					routine_arg = malloc(sizeof(t_routine_arg));
					routine_arg->nmap = (t_nmap *)nmap_list_node->data;
					routine_arg->port_range = step_count + remainder;
					routine_arg->scans = nmap_input->scans;
					routine_arg->ports = next_head_ports(nmap_input->ports, offset);
					routine_arg->src_addr = src_addr;
					routine_arg->dest_addr = dest_addr;
					routine_arg->nmap->closed_ports = NULL;
					routine_arg->nmap->open_ports = NULL;
					// create the thread
					int error = pthread_create(((pthread_t *)thread_node->data), NULL, thread_routine, routine_arg);
					if (error != 0)
						print_error("Pthread Create: %s\n", strerror(error));
					remainder = remainder > 0 ? 0 : remainder;
					offset += routine_arg->port_range;
					free(thread);
				}
				join_threads(threads, (t_nmap **)&nmap_list_node->data);
				list_free(&threads);
				free(nmap_node);
			}
			list_add(&nmap, nmap_list_node);
		}
		printf("\033[0;32mScanning ip: %s is Finished\033[0m\n", nmap_input->ipaddr->ip_addr);
		printf("\033[0;33mScan Took %.3f seconds\033[0m\n", calculate_scan_time(&sending_time));
		free(dest_addr);
		nmap_input->ipaddr = nmap_input->ipaddr->next;
	}
	nmap_print(nmap, scan_counter);
}

