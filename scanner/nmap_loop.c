#include "../ft_nmap.h"

void nmap_loop(t_input *nmap_input)
{
    t_list	*nmap;
	t_nmap	*nmap_node;
	t_list 	*nmap_list_node;
	t_list	*threads;

	nmap = NULL;
    while(nmap_input->ipaddr)
	{
		if (nmap_input->ipaddr->discovery)
		{
			threads = NULL;
			nmap_node = create_nmap_node(&nmap_input->ipaddr);
			nmap_list_node = list_new(nmap_node, sizeof(t_list));
			// iterate through the threads
			for (int i = 0; i < nmap_input->thread_count; i++)
			{
				pthread_t *thread;

				thread = malloc(sizeof(pthread_t));
				list_add(&threads, list_new(&thread, sizeof(pthread_t *)));
				t_routine_arg routine_arg;

				routine_arg.nmap = nmap_node;
				routine_arg.port_range = nmap_input->port_count;
				routine_arg.scans = nmap_input->scans;
				routine_arg.ports = nmap_input->ports;
				// create the thread
				int error = pthread_create(thread, NULL, thread_routine, &routine_arg);
				if (error != 0)
				{
					error_print(strerror(error));
					exit(1);
				}	
			}
			// join the threads (wait for all threads to finish)
			join_threads(threads);
			list_free(&threads);
            // sorting the result by port number
			list_add(&nmap, nmap_list_node);
		}
		nmap_input->ipaddr = nmap_input->ipaddr->next;
	}
}