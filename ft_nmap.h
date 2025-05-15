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

#define MIN 25000
#define MAX 65000

#define	ALL_SCAN  -1
#define	SYN_SCAN  0
#define NULL_SCAN 4
#define ACK_SCAN  18
#define	FIN_SCAN  9
#define	XMAS_SCAN 13
#define UDP_SCAN  22
#define CLOSED 5
#define	OPEN_FILTERED 11
#define OPEN 1
#define FILTERED 2
#define TTL 128
#define UNFILTERED 3
#define	UNASSIGNED 6


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
	struct s_scan	*next;
}	t_scan;

typedef struct s_port
{
	int				port_number;
	int				service;
	int				category;
	t_scan			*scans;
	struct s_port	*next;
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

typedef struct s_thread_res {
	t_port	*closed_ports;
	t_port	*open_ports;
}t_thread_res;


typedef struct s_pseudo_header {
    uint32_t	source_address;
    uint32_t	dest_address;
    uint8_t		placeholder;
    uint8_t		protocol;
    uint16_t	tcp_length;
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

typedef struct s_service
{
	char	*tcp_srv;
	char	*udp_srv;
} t_srv;

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

int				add_node(t_ipaddr **list, char *ipaddr, struct sockaddr *sockaddr, socklen_t addrlen, bool disc);
bool			host_discovery(char *ipaddr, struct sockaddr *sockaddr, socklen_t addr_len);
bool			perform_scan(t_input *input, t_ipaddr *ipaddr, int scan);
void			print_error(const char *format, ...);
unsigned short	checksum(void *b, int len);
t_list			*return_all_scans(void);

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
void	join_threads(t_list *threads, t_nmap **nmap_list);

// nmap strucuts
t_scan	*create_scan(int type);
t_port	*create_port(int port_nb);
t_nmap	*create_nmap(t_ipaddr *ipaddr);
void	scanner(void);

// scans
int					udp_scan(char *ip, int port);
void				generate_ip_header(t_probe *probe_request, struct in_addr ip_source, struct in_addr ip_destination);
void				generate_tcp_header(int port, int scan_type, t_probe *probe_request, struct in_addr ip_source, struct in_addr ip_destination);
struct sockaddr_in	get_local_address(void);
t_sock 				get_target_address(const char *target_addr, int port);
bool				check_time_out(struct timeval *start_time);
int					syn_handler(const u_char *packet);
const u_char		*packet_receive(char *filter_exp);
int					handle_packet(const u_char *packet, int scan);
void				prob_packet(const char *ip_addr, const int port, const int send_socket, int scan_type);
char				*build_filter(const char *ip, int port);
int					tcp_scan(const char *ip_addr, int scan_type, int port, int socketk, int);
int					ack_handler(const u_char *packet);
int					syn_handler(const u_char *packet);
int					FNX_handler(const u_char *packet);
void				scan_add(t_scan **scans, t_scan *new_scan);
void				port_add(t_port **ports, t_port *new_port);

// ouput
char	*macro_string_rep(int macro);
char    *result_formater(int scan, int result);
void    padding(int space_counter);
void    print_table(char *title, t_port *data, int scan_counter, t_srv *services);
void	print_stats(const char *ip, int port_count, t_list *scans, int thread_count);
void	nmap_print(t_list *nmap_list, int scan_count, t_srv *services);

// utils
int					generate_random_id(void);
t_srv				*service_mapper(void);

#endif
