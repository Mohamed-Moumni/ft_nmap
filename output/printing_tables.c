#include "../ft_nmap.h"

char *macro_string_rep(int macro)
{
    char *to_return;

    switch (macro)
    {
        case SYN_SCAN:
            to_return = "SYN";
            break;
        case NULL_SCAN:
            to_return = "NULL";
            break;
        case ACK_SCAN:
            to_return = "ACK";
            break;
        case FIN_SCAN:
            to_return = "FIN";
            break;
        case XMAS_SCAN:
            to_return = "XMAS";
            break;
        case UDP_SCAN:
            to_return = "UDP";
            break;
        case OPEN:
            to_return = "Open";
            break;
        case CLOSED:
            to_return = "Closed";
            break;
        case FILTERED:
            to_return = "Filtered";
            break;
        case OPEN_FILTERED:
            to_return = "Open|Filtered";
            break;
        case UNFILTERED:
            to_return = "Unfiltered";
            break;
        case UNASSIGNED:
            to_return = "Unassigned";
            break;
        default:
            return NULL;
    }
    return to_return;
}

char    *result_formater(int scan, int result)
{
    char    *scan_string = macro_string_rep(scan);
    char    *result_string = macro_string_rep(result);
    int     buf_size = strlen(result_string) + strlen(scan_string) + 3;
    char    *to_return = malloc(buf_size);

    snprintf(to_return, buf_size, "%s(%s)", scan_string, result_string);
    return to_return;
}

void    padding(int space_counter)
{
    while (space_counter)
    {
        printf(" ");
        space_counter--;
    }
    printf(" | ");
}

void    print_table(char *title, t_port *data, int scan_counter, t_srv *services)
{
    char    *result;
    char    *svc_name;
    char    *conclusion;

    printf("%s:\n", title);
    printf("%-10s | %-30s | %-30s | %-10s\n", "Port", "Service Name (if applicable)", "Results", "Conclusion");
    printf("--------------------------------------------------------------------------------------------\n");
    while (data)
    {
        result = result_formater(data->scans->type, data->scans->state);
        svc_name = services[data->port_number - 1].tcp_srv;
        conclusion = macro_string_rep(data->category);
        printf("%-10d | %-30s | %-30s | %-10s\n", data->port_number, svc_name, result, conclusion);
        if (scan_counter > 1)
        {
            data->scans = data->scans->next;
            while (data->scans)
            {
                padding(10);
                padding(30);
                result = result_formater(data->scans->type, data->scans->state);
                printf("%s\n", result);
                data->scans = data->scans->next;
            }
        }
        free(result);
        data = data->next;
    }
}

void print_stats(const char *ip, int port_count, t_list *scans, int thread_count)
{
    t_scan *scan;

    printf("Scan Configurations\n");
    printf("Target Ip-Address: %s\n", ip);
    printf("No of Ports to scan: %d\n", port_count);
    printf("Scans to be performed: ");
    while (scans)
    {
        scan = (t_scan *)scans->data;
        printf("%s ", macro_string_rep(scan->type));
        scans = scans->next;
    }
    printf("\nNo of threads: %d\n", thread_count);
    printf("Scanning...\n");
}
