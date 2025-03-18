/* ************************************************************************** */
/*                                                                            */
/*                                                        :::      ::::::::   */
/*   ft_split.c                                         :+:      :+:    :+:   */
/*                                                    +:+ +:+         +:+     */
/*   By: workshop <workshop@student.42.fr>          +#+  +:+       +#+        */
/*                                                +#+#+#+#+#+   +#+           */
/*   Created: 2021/11/05 11:42:34 by yait-iaz          #+#    #+#             */
/*   Updated: 2025/03/18 13:16:53 by workshop         ###   ########.fr       */
/*                                                                            */
/* ************************************************************************** */

#include "../ft_nmap.h"

static int	count_d(const char *s, char c)
{
	int		i;
	int		count;
	int		end;

	i = 0;
	count = 0;
	end = (int)strlen(s) - 1;
	while (s[i] == c)
		i++;
	while (s[end] == c)
		end--;
	end += 1;
	while (s[i] && end >= i)
	{
		if (s[i] == c && s[i - 1] != c)
			count++;
		i++;
	}
	if (end == (int)strlen(s))
		count++;
	return (count);
}

static char	*ft_strdupi(const char *s1, int l)
{
	int		i;
	char	*str;

	i = 0;
	str = malloc(sizeof(char) * (l + 1));
	if (!str)
		return (0);
	while (s1[i] && l > i)
	{
		str[i] = s1[i];
		i++;
	}
	str[i] = '\0';
	return (str);
}

static int	l_i(const char *s, char c, int i, int *l)
{
	while (s[i] == c && s[i])
		i++;
	while (s[i] != c && s[i])
	{
		(*l)++;
		i++;
	}
	return (i);
}

void	free_t(char **str, int count)
{
	while (str[count])
	{
		free(str[count]);
		count--;
	}
	free(str);
	str = NULL ;
}

char	**ft_split(char const *s, char c)
{
	int		i;
	int		j;
	int		l;
	int		count;
	char	**str;

	i = 0;
	j = 0;
	if (!s)
		return (0);
	count = count_d(s, c);
	str = (char **)malloc(sizeof(char *) * (count + 1));
	if (!str)
		return (0);
	while (s[i] && count > j)
	{
		l = 0;
		i = l_i(s, c, i, &l);
		str[j] = ft_strdupi(&s[i - l], l);
		if (!str[j])
			free_t(str, count);
		j++;
	}
	str[j] = 0;
	return (str);
}
