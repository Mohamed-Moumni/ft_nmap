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

#define	ALL_SCAN  -1
#define	SYN_SCAN  0
#define NULL_SCAN 4
#define	FIN_SCAN  9
#define	XMAS_SCAN 13
#define ACK_SCAN  18
#define UDP_SCAN  22

typedef struct s_ipaddr {
	char			*ip_addr;
	struct sockaddr *sock_addr;
	socklen_t       addr_len;
	bool			discovery;
	struct s_ipaddr	*next;
}	t_ipaddr;

typedef struct s_input {
	int 		scan;
	int			port_range;
	int			port_start;
	int			thread_count;
	t_ipaddr	*ipaddr;
}	t_input;

typedef struct s_connect {
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

bool    parse_ip(char   *param, t_input *input);
bool    parse_ip_file(char  *param, t_input *input);
bool    parse_speedup(char  *param, t_input *input);
bool    parse_scan(char *param, t_input *input);
bool    parse_ports(char    *param, t_input *input);

char	**ft_split(char const *s, char c);
bool	validate_ipaddr(char **splited);
int		ft_isnum(char *str);
int		ft_d_strlen(char **av);
bool	parse_ip_hostname(char *param, t_input *input);
char	*get_next_line(int fd);

int		add_node(t_ipaddr **list, char *ipaddr, struct sockaddr *sockaddr, socklen_t addrlen, bool disc);
bool	host_discovery(t_ipaddr *ip_addr);


#endif
