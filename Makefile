SRC = ./main.c ./parser/parser.c ./parser/outils.c ./parser/ft_split.c \
	  ./parser/ip_file_parse.c ./parser/gnl.c ./parser/ipaddr.c ./network_mapper/host_discovery.c \
	  ./scanner/utils.c ./network_mapper/threads.c ./network_mapper/nmap_loop.c ./scanner/UDP.c ./scanner/syn_scan.c

OBJ = $(SRC:.c=.o)

NAME = ft_nmap

HEADERS = ./ft_nmap.h

CC = gcc

FLAGS = 
#-Wall -Wextra -Werror

all: $(NAME)

$(NAME): $(OBJ) $(HEADERS)
	$(CC) $(FLAGS) $(OBJ) -o $(NAME) -lm -lpthread -lpcap

%.o : %.c $(HEADERS)
	$(CC) $(FLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

hoho: all clean
	clear

re: fclean all