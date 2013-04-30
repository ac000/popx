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
#include <strings.h>
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

struct msg_hdrs {
	int msg;
	size_t len;
	char *from;
	char *subject;
	char *date;
};

static int nr_messages;
static int sockfd;
static char buf[BUF_SIZE];
static struct msg_hdrs *msg_hdrs;

static void print_usage(void)
{
	printf("Usage: popx <host> <username>\n");
}

static void print_help(void)
{
	printf("\nList of useful commands:- \n");
	printf("    TOP n [l]   View the headers of message n with optional "
			"number of lines\n");
	printf("                [l] of body\n");
	printf("    RETR n      Retrieve message n\n");
	printf("    DELE n      Delete message n\n");
	printf("    RSET        Reset the session to its initial state\n");
	printf("    LIST        List messages (POP)\n");
	printf("    LISTX       popx message list\n");
	printf("    QUIT\n");
}

static void free_msg_hdrs(void)
{
	int i;

	for (i = 0; i < nr_messages; i++) {
		free(msg_hdrs[i].from);
		free(msg_hdrs[i].subject);
		free(msg_hdrs[i].date);
	}
	free(msg_hdrs);
	msg_hdrs = NULL;
	nr_messages = 0;
}

static char *strchomp(char *string)
{
	string[strcspn(string, "\r\n")] = '\0';
	return string;
}

static ssize_t read_pop_response_sync(int fd, void *buf, size_t count)
{
	ssize_t bytes_read;
	ssize_t total = 0;

	for (;;) {
		bytes_read = read(sockfd, buf + total, count - total);
		/*
		 * This might not be fool proof, but we need some way
		 * to know when to stop reading.
		 */
		if (strstr(buf + total, "\r\n.\r\n"))
			break;
		total += bytes_read;
	}
	return total += bytes_read;
}

static void display_message_list(void)
{
	int i;

	for (i = 0; i < nr_messages; i++) {
		printf("% 4d: %s\n", msg_hdrs[i].msg, msg_hdrs[i].subject);
		printf("\t%s\n", msg_hdrs[i].from);
		printf("\t%s\n", msg_hdrs[i].date);
	}
}

static void get_message_hdrs(int message, size_t len)
{
	FILE *hdrs;
	char *hptr;
	char msg[BUF_SIZE];
	size_t hsize;
	ssize_t bytes_read;
	int index;

	snprintf(msg, sizeof(msg), "TOP %d\r\n", message);
	write(sockfd, msg, strlen(msg));

	memset(buf, 0, sizeof(buf));
	read_pop_response_sync(sockfd, buf, BUF_SIZE);

	hdrs = open_memstream(&hptr, &hsize);
	fprintf(hdrs, "%s", buf);
	rewind(hdrs);

	index = ++nr_messages - 1;
	msg_hdrs = realloc(msg_hdrs, sizeof(struct msg_hdrs) * nr_messages);
	memset(&msg_hdrs[index], 0, sizeof(struct msg_hdrs));

	msg_hdrs[index].msg = message;
	msg_hdrs[index].len = len;
	do {
		char *line = NULL;
		char *hdr;
		size_t size;

		bytes_read = getline(&line, &size, hdrs);
		if (bytes_read == -1)
			goto out;
		if (strncasecmp(line, "subject: ", 9) == 0) {
			hdr = strchr(line, ' ') + 1;
			strchomp(hdr);
			msg_hdrs[index].subject = strdup(hdr);
		} else if (strncasecmp(line, "from: ", 6) == 0) {
			hdr = strchr(line, ' ') + 1;
			strchomp(hdr);
			msg_hdrs[index].from = strdup(hdr);
		} else if (strncasecmp(line, "date: ", 6) == 0) {
			hdr = strchr(line, ' ') + 1;
			strchomp(hdr);
			msg_hdrs[index].date = strdup(hdr);
		}
out:
		free(line);
	} while (bytes_read > 0);

	fclose(hdrs);
	free(hptr);
}

static void get_message_list(void)
{
	FILE *list;
	char *lptr;
	size_t lsize;
	ssize_t bytes_read;

	write(sockfd, "LIST\r\n", 6);
	read_pop_response_sync(sockfd, buf, BUF_SIZE);

	list = open_memstream(&lptr, &lsize);
	fprintf(list, "%s", buf);
	rewind(list);

	do {
		char *line = NULL;
		char *string;
		size_t len;
		size_t mlen;
		int message;

		bytes_read = getline(&line, &len, list);
		if (bytes_read == -1 || line[0] == '-' || line[0] == '+' ||
		    line[0] == '.' || strlen(line) == 0)
			goto next;
		string = strdup(line);
		message = atoi(strtok(string, " "));
		mlen = atol(strtok(NULL, " "));
		get_message_hdrs(message, mlen);
		free(string);
next:
		free(line);
		line = NULL;
	} while (bytes_read > 0);

	fclose(list);
	free(lptr);
}

static void do_connect(const char *host, const char *username,
		       const char *password)
{
	struct addrinfo hints;
	struct addrinfo *res;
	ssize_t bytes_read;

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

static int msg_get(void)
{
	ssize_t bytes_read;

	memset(buf, 0, sizeof(buf));
	bytes_read = read(sockfd, buf, BUF_SIZE);
	printf("%s", buf);

	if (bytes_read == 0)
		return -1;
	else
		return 0;
}

static void msg_send(const char *comm)
{
	char msg[BUF_SIZE];
	int len;

	len = snprintf(msg, sizeof(msg), "%s\r\n", comm);
	write(sockfd, msg, len);

	msg_get();
}

static void parse_command(const char *comm)
{
	if (strcasecmp(comm, "exit") == 0)
		write(sockfd, "QUIT\r\n", 6);
	else if (strcasecmp(comm, "help") == 0)
		print_help();
	else if (strcasecmp(comm, "listx") == 0)
		display_message_list();
	else
		msg_send(comm);

	if (strncasecmp(comm, "dele", 4) == 0) {
		free_msg_hdrs();
		get_message_list();
	}
}

static void get_command(void)
{
	size_t len;
	char *comm = NULL;

	getline(&comm, &len, stdin);
	strchomp(comm);
	if (strlen(comm) > 0)
		parse_command(comm);
	free(comm);
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

	get_message_list();
	display_message_list();

	FD_ZERO(&rfds);
	for (;;) {
		printf("popx %s> ", argv[1]);
		fflush(stdout);
		FD_SET(STDIN_FILENO, &rfds);
		FD_SET(sockfd, &rfds);
		select(sockfd + 1, &rfds, NULL, NULL, NULL);
		if (FD_ISSET(sockfd, &rfds)) {
			ret = msg_get();
			if (ret == -1) {
				printf("Connection closed by foreign host\n");
				break;
			}
		} else {
			get_command();
		}
	}

	close(sockfd);
	free_msg_hdrs();

	exit(EXIT_SUCCESS);
}
