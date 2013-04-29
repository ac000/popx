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

static void free_msg_hdrs(void)
{
	int i;

	for (i = 0; i < nr_messages; i++) {
		free(msg_hdrs[i].from);
		free(msg_hdrs[i].subject);
		free(msg_hdrs[i].date);
	}
	free(msg_hdrs);
}

static char *strchomp(char *string)
{
	string[strcspn(string, "\r\n")] = '\0';
	return string;
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
	ssize_t rlen = 0;
	ssize_t bytes_read;

	memset(buf, 0, sizeof(buf));
	snprintf(msg, sizeof(msg), "TOP %d\r\n", message);
	write(sockfd, msg, strlen(msg));

	for (;;) {
		bytes_read = read(sockfd, buf + rlen, BUF_SIZE - rlen);
		rlen += bytes_read;
		/*
		 * This might not be fool proof, but we need some way
		 * to know when to stop reading.
		 */
		if (strstr(buf, "\r\n\r\n.\r\n"))
			break;
	}

	hdrs = open_memstream(&hptr, &hsize);
	fprintf(hdrs, "%s", buf);
	rewind(hdrs);

	nr_messages++;
	msg_hdrs = realloc(msg_hdrs, sizeof(struct msg_hdrs) * nr_messages);
	msg_hdrs[message - 1].msg = message;
	msg_hdrs[message - 1].len = len;
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
			msg_hdrs[message - 1].subject = strdup(hdr);
		} else if (strncasecmp(line, "from: ", 6) == 0) {
			hdr = strchr(line, ' ') + 1;
			strchomp(hdr);
			msg_hdrs[message - 1].from = strdup(hdr);
		} else if (strncasecmp(line, "date: ", 6) == 0) {
			hdr = strchr(line, ' ') + 1;
			strchomp(hdr);
			msg_hdrs[message - 1].date = strdup(hdr);
		}
out:
		free(line);
		line = NULL;
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
	bytes_read = read(sockfd, buf, BUF_SIZE);

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

static void msg_send(const char *comm)
{
	char msg[BUF_SIZE];
	int len;

	len = snprintf(msg, sizeof(msg), "%s\r\n", comm);
	write(sockfd, msg, len);
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
	int ret = 0;
	size_t len;
	char *comm = NULL;

	getline(&comm, &len, stdin);
	strchomp(comm);
	if (strlen(comm) == 0)
		goto out;
	ret = parse_command(comm);
out:
	free(comm);

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

	get_message_list();
	display_message_list();
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
	free_msg_hdrs();

	exit(EXIT_SUCCESS);
}
