#include "../ft_nmap.h"

void* thread_routine(void* arg)
{ 
    (void)arg;
    printf("Thread Routine Method!!\n");
    
    t_routine_arg   *routine_arg;
    
    routine_arg = (t_routine_arg *)arg;
    printf("Port Range: %d\n", routine_arg->port_range);
    // starting the process of port scanning for the start to the end
    // for each port do the available scan that should performed
    // while (routine_arg->start_port <= routine_arg->end_port)
    // {

    //     routine_arg->start_port++;
    // }
    return NULL;
}

void join_threads(t_list *threads)
{
    printf("Join Threads\n");
    t_list *thread_temp;

    thread_temp = threads;
    while(thread_temp)
    {
        pthread_t thread;

        thread = *((pthread_t *)thread_temp->data);
        int res = pthread_join(thread, NULL);
        if (res)
        {
            error_print(strerror(res));
            exit(1);
        }
        thread_temp = thread_temp->next;
    }
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