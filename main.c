#include "ft_nmap.h"

void print_help()
{
	printf("Help Screen\n");
	printf("Usage:	ft_nmap [--ports [NUMBER/RANGED]] --ip IP_ADDRESS [--speedup [NUMBER] [--scan [TYPE]]\n");
	printf("or:		ft_nmap [--ports [NUMBER/RANGED]] --file FILE [--speedup [NUMBER] [--scan [TYPE]]\n");
	printf("--help      Print this help screen\n");
	printf("--ports     Ports to scan (eg: 1-10 or 10)\n");
	printf("--ip        ip addresses to scan in do fromat (IPv4)\n");
	printf("--file      File name containing IP addresses to scan\n");
	printf("--speedup   [250 max] number of parallel threads to use\n");
	printf("--scan      SYN/NULL/FIN/XMAS/ACK/UDP\n");
	exit(0);
}

int main(int argc, char **argv)
{
	int		i;
	bool	ipaddr;
	t_input	input;

	i = 1;
	ipaddr = false;
	input.scans = NULL;
	input.ipaddr = NULL;
	input.ports = NULL;
	input.port_count = 0;
	input.thread_count = 0;
	if (argc == 1 || (argc == 2 && !strcmp("--help", argv[1])))
		print_help();
	if (argc % 2 == 0)
		print_help();
	// loop through the args
	while (argc > i)
	{
		// printf("hoho %s\n", argv[i]);
		if (!strcmp(argv[i], "--ip")) // this one handles "--ip"
		{
			// this one handle the duplication usage of --file and --ip
			if (ipaddr)
			{
				printf("Error: only use --file or --ip\n");
				print_help();
			}
			if (!parse_ip(argv[i + 1], &input))
				print_help();
			ipaddr = true;
		}
		else if (!strcmp(argv[i], "--file")) // this one handles "--file"
		{
			// this one handle the duplication usage of --file and --ip
			if (ipaddr)
			{
				printf("Error: only use --file or --ip\n");
				print_help();
			}
			if (!parse_ip_file(argv[i + 1], &input))
				print_help();
			ipaddr = true;
		}
		// this one handles "--speedup" pay attention to the &&
		else if (!strcmp(argv[i], "--speedup") && parse_speedup(argv[i + 1], &input)); 
		// this one handles "--scan" pay attention to the &&
		else if (!strcmp(argv[i], "--scan") && parse_scan(argv[i + 1], &input));
		// this one handles "--ports" pay attention to the &&
		else if (!strcmp(argv[i], "--ports") && parse_ports(argv[i + 1], &input));
		else
			print_help(); // handle mistaken args
		// we skip the option's value and get to the next key
		i += 2;
	}

	// checks if the only required field is there
	if (!ipaddr)
		print_help();
	if (!input.scans)
		input.scans = return_all_scans();
	if (!input.ports)
	{
		input.ports = return_default_ports();
		input.port_count = node_counter(input.ports);
	}
	nmap_loop(&input);
	return 0;
}
 