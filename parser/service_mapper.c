#include "../ft_nmap.h"

t_srv *service_mapper(void)
{
    t_srv *services = malloc(sizeof(t_srv) * 65533);

    if (!services)
        print_error("Services Malloc Error");
    
    int fd = open("./parser/service_names.txt", O_RDONLY);
    if (fd < 0)
        print_error("open File Error");
    char *line = get_next_line(fd);
    while (line)
    {
        char **srv = ft_split(line, ' ');
        char **port_prot = ft_split(srv[1],'/');
        if (!strcmp(port_prot[1], "tcp"))
        {
            int port = atoi(port_prot[0]);
            services[port - 1].tcp_srv = srv[0];
        }
        else if (!strcmp(port_prot[1], "udp"))
        {
            int port = atoi(port_prot[0]);
            services[port - 1].tcp_srv = srv[0];
        }
        line = get_next_line(fd);
    }
    close(fd);
    return services;
}
