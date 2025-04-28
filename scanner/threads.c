#include "ft_nmap.h"

void* thread_routine(void* arg)
{ 
    t_routine_arg   *routine_arg;

    routine_arg = (t_routine_arg *)arg;
    // starting the process of port scanning for the start to the end
    // for each port do the available scan that should performed
}

void join_threads(t_list *threads)
{
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