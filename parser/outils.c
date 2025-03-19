#include "../ft_nmap.h"

int	ft_isnum(char *str)
{
	int i = 0;
	while (str[i] != '\0')
	{
		if (str[i] < '0' || str[i] > '9')
			return 0;
		i++;
	}
	return 1;
}

bool validate_ipaddr(char **splited){
	int i = 0;
	while (splited[i]) {
		int ip_byte = atoi(splited[i]);
		if (ip_byte == 0 && strcmp(splited[i], "0"))
			return false;
		if (ip_byte < 0 || ip_byte > 254)
			return false;
		i++;
	}
	if (i != 4)
		return false;
	return true;
}

int	ft_d_strlen(char **av)
{
	int	i;

	i = 0;
	while (av[i])
		i++;
	return (i);
}