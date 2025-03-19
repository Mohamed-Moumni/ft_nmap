#ifndef FTNMAP_H
# define FTNMAP_H

#include <stdio.h>
# include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <math.h>

#define	SYN_SCAN 0
#define NULL_SCAN 4
#define	FIN_SCAN	9
#define	XMAS_SCAN 13
#define ACK_SCAN 18
#define UDP_SCAN 22


typedef struct s_connect{
	char			*argv;
	char            *ip_addr;
	int             sockfd;
	struct sockaddr *sock_addr;
	socklen_t       addr_len;
}   t_connect;

typedef struct icmp_header {
	u_int8_t	type;
	u_int8_t	code;
	u_int16_t	checksum;
	u_int16_t	id;
	u_int16_t	sequence;
}	t_icmp_header;

extern t_connect connection;

bool    parse_ip(char   *param);
bool    parse_ip_file(char  *param);
bool    parse_speedup(char  *param);
bool    parse_scan(char *param);
bool    parse_ports(char    *param);

char	**ft_split(char const *s, char c);
bool	validate_ipaddr(char **splited);
int		ft_isnum(char *str);
int		ft_d_strlen(char **av);
bool	parse_ip_hostname(char *param);
char	*get_next_line(int fd);


#endif
