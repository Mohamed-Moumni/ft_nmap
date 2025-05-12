#ifndef FTNMAP_H
# define FTNMAP_H

#define _GNU_SOURCE
#define _BEGIN_DECLS

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/time.h>
#include <math.h>
#include <pthread.h>
#include <pcap.h>

#define	ALL_SCAN  -1
#define	SYN_SCAN  0
#define NULL_SCAN 4
#define ACK_SCAN  18
#define	FIN_SCAN  9
#define	XMAS_SCAN 13
#define UDP_SCAN  22
#define CLOSED 0
#define OPEN 1
#define FILTERED 2
#define TTL 128

typedef struct s_list
{
	void	*data;
	struct s_list *next;
}	t_list;

typedef struct s_ipaddr {
	char			*ip_addr;
	struct sockaddr *sock_addr;
	socklen_t       addr_len;
	bool			discovery;
	struct s_ipaddr	*next;
}	t_ipaddr;

typedef struct s_input {
	t_list		*scans;
	t_list		*ports;
	int			port_count;
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

typedef struct s_scan
{
	int				type;
	int				state;
}	t_scan;

typedef struct s_port
{
	int				port_number;
	int				service;
	int				category;
	t_scan			*scans;
}	t_port;

typedef struct s_nmap
{
	t_ipaddr			*ipaddr;
	t_port				*open_ports;
	t_port				*closed_ports;
}	t_nmap;

typedef struct s_routine_arg {
	t_nmap	*nmap;
	t_list	*ports;
	t_list	*scans;
	int		port_range;

} t_routine_arg;

typedef struct s_pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
}t_pseudo_header;

typedef struct s_probe
{
	struct ip		ip_header;
	struct tcphdr	tcp_header;
} t_probe;

typedef struct sock{
	struct sockaddr_in socket;
	socklen_t socket_len;
} t_sock;

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
bool	host_discovery(char *ipaddr, struct sockaddr *sockaddr, socklen_t addr_len);
bool	perform_scan(t_input *input, t_ipaddr *ipaddr, int scan);
void	print_error(const char *format, ...);
unsigned short	checksum(void *b, int len);

// list methods
t_list	*list_new(void *data, size_t data_size);
void	list_add(t_list **list_item, t_list *new_item);
void	list_free(t_list **list_tem);
int		node_counter(t_list *list_to_count);

// nmap strucuts
t_scan	*create_scan(int type);
t_port	*create_port(int port_nb);
t_nmap	*create_nmap_node(t_ipaddr *ipaddr);
void	nmap_loop(t_input *nmap_input);
t_list	*next_head_ports(t_list *ports, int offset);

// crafting the tcp header
char *tcp_header(int tcp_byte);

// threads
void	*thread_routine(void* arg);
void	join_threads(t_list *threads);

// nmap strucuts
t_scan	*create_scan(int type);
t_port	*create_port(int port_nb);
t_nmap	*create_nmap(t_ipaddr *ipaddr);
void	scanner(void);

#endif
