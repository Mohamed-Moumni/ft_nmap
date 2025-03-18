SRC = ./main.c ./parser/parser.c ./parser/outils.c ./parser/ft_split.c

OBJ = $(SRC:.c=.o)

NAME = ft_nmap

HEADERS = ./ft_nmap.h

CC = gcc

FLAGS = 
#-Wall -Wextra -Werror

all: $(NAME)

$(NAME): $(OBJ) $(HEADERS)
	$(CC) $(FLAGS) $(OBJ) -o $(NAME) -lm

%.o : %.c $(HEADERS)
	$(CC) $(FLAGS) -c $< -o $@

clean:
	rm -f $(OBJ)

fclean: clean
	rm -f $(NAME)

hoho: all clean
	clear

re: fclean all