#include "../ft_nmap.h"

bool    parse_ip(char   *param)
{
    char **splited = ft_split(param, '.');
    if (!validate_ipaddr(splited))
    {
        printf("ip: Invalid IP address\n");
        return (false);
    }
    return true;
}

bool    parse_ip_file(char  *param)
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
        if (!parse_ip_hostname(line))
        {
            printf("ip file: Invalid IP file\n");
            return (false);
        }
        line = get_next_line(fd);
    }
    return true;
}

bool    parse_speedup(char  *param)
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
    return true;
}

bool    parse_scan(char *param)
{
    char    *scans = "SYN/NULL/FIN/XMAS/ACK/UDP";
    char    *ptr_pos = strstr(scans, param);
    if (!ptr_pos)
    {
        printf("scan: Invalid scan value\n");
        return (false);
    }
    int     index_pos = ptr_pos - scans;
    return true;
}

bool    parse_ports(char    *param)
{
    int min = 0;
    int max = 0;
    int result;

    if (strchr(param, '-'))
    {
        char **splited = ft_split(param, '-');
        int  splited_len = ft_d_strlen(splited);
        if (splited_len != 2 || !ft_isnum(splited[0]) || !ft_isnum(splited[1]))
        {
            printf("ports: Invalid ports value\n");
            return (false);
        }
        min = atoi(splited[0]);
        max = atoi(splited[1]);
        result = max - min;
    }
    else {
        if (!ft_isnum(param))
        {
            printf("ports: Invalid ports value\n");
            return (false);
        }
        result = atoi(param);
    }
    if (result <= 0 || result > 1024)
    {
        printf("ports: Invalid ports value (min = 1, max = 1024)\n");
        return (false);
    }
    return true;
}