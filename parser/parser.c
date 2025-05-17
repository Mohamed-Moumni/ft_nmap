#include "../ft_nmap.h"

bool    parse_ip(char   *param, t_input *input)
{
    if (!parse_ip_hostname(param, input))
    {
        printf("ip: Invalid IPv4/hostname\n");
        return false;
    } 
    return true;
}

bool    parse_ip_file(char  *param, t_input *input)
{
    int fd = open(param, O_RDONLY);
    if (fd < 0)
    {
        printf("ip file: IP file cannot be open\n");
        return (false);
    }
    char *line = get_next_line(fd);
    while (line)
    {
        if (!parse_ip_hostname(line, input))
        {
            printf("ip file: Invalid IP file\n");
            return (false);
        }
        line = get_next_line(fd);
    }
    return true;
}

bool    parse_speedup(char  *param, t_input *input)
{
    if (!ft_isnum(param))
    {
        printf("speedup: Invalid speedup value\n");
        return (false);
    }
    int speedup = atoi(param);
    if ((strcmp(param, "0") && speedup == 0) || speedup < 0 || speedup > 250)
    {
        printf("speedup: Invalid speedup value\n");
        return (false);
    }
    input->thread_count = speedup;
    return true;
}

bool    parse_scan(char *param, t_input *input)
{
    char    *scans = "SYN/NULL/FIN/XMAS/ACK/UDP";
    char    **slash_seperated = ft_split(param, '/');
    int     i = 0;

    while (slash_seperated[i])
    {
        // printf("hoho %s\n", slash_seperated[i]);
        char    *ptr_pos = strstr(scans, slash_seperated[i]);
        if (!ptr_pos)
        {
            printf("scans: Invalid scan type\n");
            return (false);
        }
        int     index_pos = (int)(ptr_pos - scans);
        list_add(&input->scans, list_new(&index_pos, sizeof(int)));
        i++;
    }
    return true;
}

bool    parse_ports(char    *param, t_input *input)
{
    int min = 0;
    int max = 0;
    int result;
    int i = 0;
    t_list *new_port;
    char **commas_seperated = ft_split(param, ',');
    char **splited;

    if (!commas_seperated)
        return false;
    while (commas_seperated[i])
    {
        if (strchr(commas_seperated[i], '-'))
        {
            splited = ft_split(commas_seperated[i], '-');
            int  splited_len = ft_d_strlen(splited);
            if (splited_len != 2 || !ft_isnum(splited[0]) || !ft_isnum(splited[1]))
            {
                printf("ports: Invalid ports value\n");
                return (false);
            }
            min = atoi(splited[0]);
            max = atoi(splited[1]);
            if (min > max || max - min > 1024)
            {
                printf("ports: Invalid range ports\n");
                return (false);
            }
            while (min <= max)
            {
                new_port = list_new(&min, sizeof(int));
                list_add(&input->ports, new_port);
                min++;
            }
        }
        else
        {
            if (!ft_isnum(commas_seperated[i]))
            {
                printf("ports: Invalid ports value\n");
                return (false);
            }
            result = atoi(commas_seperated[i]);
            if (result == 0)
            {
                printf("Ports: Invalid ports value\n");
                return false;
            }
            new_port = list_new(&result, sizeof(int));
            list_add(&input->ports, new_port);
        }
        i++;
    }
    input->port_count = node_counter(input->ports);
    if (input->port_count > 1024 || !input->port_count)
        return false;
    return true;
}   