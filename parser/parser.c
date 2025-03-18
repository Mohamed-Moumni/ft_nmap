#include "../ft_nmap.h"

bool    parse_ip(char   *param)
{
    char **splited = ft_split(param, ".");
    if (!validate_ipaddr(splited))
    {
        printf("ip: Invalid IP address\n");
        exit(0);
    }
    printf("ip %s all good\n", param);
    return true;
}

bool    parse_ip_file(char  *param)
{
    printf("ip file %s is good\n", param);
}

bool    parse_speedup(char  *param)
{
    int speedup = atoi(param);
    if ((strcmp(param, "0") && speedup == 0) || speedup < 0 || speedup > 250)
    {
        printf("speedup: Invalid speedup value\n");
        exit(0);
    }
    printf("speed up %s all good\n", param);
    return true;
}

bool    parse_scan(char *param)
{
    char    *scans = "SYN/NULL/FIN/XMAS/ACK/UDP";
    char    *ptr_pos = strstr(scans, param);
    if (!ptr_pos)
    {
        printf("scan: Invalid scan value\n");
        exit(0);
    }
    int     index_pos = ptr_pos - scans;
    printf("san %d all good\n", index_pos);
    return true;
}

bool    parse_ports(char    *param)
{
    printf("ports %s is good\n", param);
}