#include "../ft_nmap.h"

void free_two_demension(char **to_free){
	int i;

	i = 0;
	while (to_free[i] != NULL)
	{
		free(to_free[i]);
		i++;
	}
	free(to_free);
}

bool	validate_hostname(char *param, t_input *input)
{
	struct addrinfo	hints;
	struct addrinfo	*res;
	int				ret;
	int				sockfd;
	struct timeval	timeout;
	bool			discovery;

	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_RAW;
	ret = getaddrinfo(param, NULL, &hints, &res);
	if (ret != 0) {
		if (ret == -2)
		    printf("ft_nmap: %s: Name or service not known\n", param);
		else if (ret == -3)
			printf("ft_nmap: %s: Temporary failure in name resulotion\n", param);
		else
		    printf("error while getting address info %i\n", ret);
		exit(ret);
	}
	char ip[32];
	while (res != NULL) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)res->ai_addr;
		if (inet_ntop(res->ai_family, &addr_in->sin_addr.s_addr, ip, 32))
		{
			discovery = host_discovery(param, res->ai_addr, res->ai_addrlen);
			add_node(&((*input).ipaddr), strdup(ip), res->ai_addr, res->ai_addrlen, discovery);
			return true;
		}
		res = res->ai_next;
	}
	return false;
}

bool	parse_ip_hostname(char *param, t_input *input)
{
	char			**splited;
	bool			discovery;

	splited = ft_split(param, '.');
	if (ft_isnum(splited[0]))
	{
		if (!validate_ipaddr(splited))
			return false;
		struct sockaddr_in *server_addr = malloc(sizeof(struct sockadd_in *));
		server_addr->sin_family = AF_INET;
		if (inet_pton(AF_INET, param, &server_addr->sin_addr) <= 0)
		{
			fprintf(stderr, "error number %i inet_pton\n", errno);
			return false;
		}
		discovery = host_discovery(param, (struct sockaddr *)server_addr, sizeof(struct sockaddr));
		add_node(&((*input).ipaddr), strdup(param), (struct sockaddr *)server_addr, sizeof(struct sockaddr), discovery);
		// I need to store those values
	}
	else {
		return (validate_hostname(param, input));
	}
	free_two_demension(splited);
	return true;
}