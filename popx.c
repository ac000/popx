/*
 * popx.c - CLI to access a POP3 mailbox, in the same vein as mailx
 *
 * Copyright (C) 2013		Andrew Clayton <andrew@digital-domain.net>
 *
 * Licensed under the GNU General Public License Version 2
 * See COPYING
 */

#define _POSIX_C_SOURCE	200809L 	/* for getline(3) */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define BUF_SIZE        8192
#define POP3_PORT	"110"

static int sockfd;
static ssize_t bytes_read;
static char buf[BUF_SIZE];

static void print_usage(void)
{
	printf("Usage: popx <host> <username>\n");
}

static void do_connect(const char *host, const char *username,
		       const char *password)
{
	struct addrinfo hints;
	struct addrinfo *res;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	getaddrinfo(host, POP3_PORT, &hints, &res);
	sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	connect(sockfd, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	bytes_read = read(sockfd, buf, BUF_SIZE);
	buf[bytes_read - 2] = '\0';
	printf("%s\n", buf);

	/* Send username */
	snprintf(buf, sizeof(buf), "USER %s\r\n", username);
	write(sockfd, buf, strlen(buf));
	bytes_read = read(sockfd, buf, BUF_SIZE);

	/* Send password */
	snprintf(buf, sizeof(buf), "PASS %s\r\n", password);
	write(sockfd, buf, strlen(buf));
	bytes_read = read(sockfd, buf, BUF_SIZE);
	buf[bytes_read - 2] = '\0';
	printf("%s\n", buf);
}

static void msg_send(const char *comm)
{
	char msg[BUF_SIZE];
	int len;

	len = snprintf(msg, sizeof(msg), "%s\r\n", comm);
	write(sockfd, msg, len);
}

static int msg_get(void)
{
	memset(buf, 0, sizeof(buf));
	bytes_read = read(sockfd, buf, BUF_SIZE);
	printf("%s", buf);

	if (bytes_read == 0)
		return -1;
	else
		return 0;
}

static int parse_command(const char *comm)
{
	if (strncmp(comm, "exit", 4) == 0)
		return -2;
	else
		msg_send(comm);
	return 0;
}

static int get_command(void)
{
	int ret;
	size_t len;
	char *comm = NULL;

	bytes_read = getline(&comm, &len, stdin);
	comm[bytes_read - 1] = '\0';
	ret = parse_command(comm);
	free(comm);
	comm = NULL;

	return ret;
}

int main(int argc, char *argv[])
{
	int ret;
	fd_set rfds;
	char password[65];
	struct termios tp;

	if (argc < 3) {
		print_usage();
		exit(EXIT_FAILURE);
	}

	printf("Password: ");
	tcgetattr(STDIN_FILENO, &tp);
	tp.c_lflag &= ~ECHO;	/* Turn ECHO off */
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &tp);
	scanf("%s[64]", password);
	tp.c_lflag |= ECHO;	/* Turn ECHO back on */
	tcsetattr(STDIN_FILENO, TCSAFLUSH, &tp);
	printf("\n");
	do_connect(argv[1], argv[2], password);
	memset(password, 0, sizeof(password));

	FD_ZERO(&rfds);
	FD_SET(STDIN_FILENO, &rfds);
	FD_SET(sockfd, &rfds);

	for (;;) {
		printf("popx %s> ", argv[1]);
		fflush(stdout);
		select(sockfd + 1, &rfds, NULL, NULL, NULL);
		if (FD_ISSET(sockfd, &rfds))
			ret = msg_get();
		else
			ret = get_command();

		if (ret == -1) {
			fprintf(stderr, "Connection closed by foreign host\n");
			break;
		} else if (ret == -2) {
			printf("Bye.\n");
			break;
		}
		FD_SET(STDIN_FILENO, &rfds);
		FD_SET(sockfd, &rfds);
	}

	close(sockfd);

	exit(EXIT_SUCCESS);
}
