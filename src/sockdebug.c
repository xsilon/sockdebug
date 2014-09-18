/*
 ============================================================================
 Name        : sockdebug.c
 Author      : s
 Version     :
 Copyright   : Your copyright
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <sys/time.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <time.h>
#include <net/if.h>

const char* interface_string = "lowpan0";
const char* src_string = "fe80::203:9a00:0:15";
const char* dest_string = "ff02::1";
struct sockaddr_in6 src_addr;
struct sockaddr_in6 dest_addr;

void send_raw_icmp(int nd_socket, struct in6_addr *dest,
		const unsigned char *icmp_body, const unsigned int icmp_len) {
	struct sockaddr_in6 addr;
	struct in6_pktinfo *pkt_info;
	struct msghdr mhdr;
	struct cmsghdr *cmsg;
	struct iovec iov;

	unsigned int if_index = if_nametoindex(interface_string);

	if (if_index <= 0) {
		printf("error finding interface %s \n",interface_string);
	}

	memset((void *) &addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(IPPROTO_ICMPV6);
	memcpy(&addr.sin6_addr, dest, sizeof(struct in6_addr));

	iov.iov_len = icmp_len;
	iov.iov_base = (caddr_t) icmp_body;

	int cmsglen = CMSG_SPACE(sizeof(struct in6_pktinfo));

	memset(&mhdr, 0, sizeof(mhdr));
	mhdr.msg_name = (caddr_t) &addr;
	mhdr.msg_namelen = sizeof(struct sockaddr_in6);
	mhdr.msg_iov = &iov;
	mhdr.msg_iovlen = 1;
	mhdr.msg_control = malloc(cmsglen);
	mhdr.msg_controllen = cmsglen;
	memset(mhdr.msg_control, 0, cmsglen);

	cmsg = CMSG_FIRSTHDR(&mhdr);
	cmsg->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmsg->cmsg_level = IPPROTO_IPV6;
	cmsg->cmsg_type = IPV6_PKTINFO;

	pkt_info = (struct in6_pktinfo *) CMSG_DATA(cmsg);
	pkt_info->ipi6_ifindex = if_index;
	pkt_info->ipi6_addr = src_addr.sin6_addr;

	sendmsg(nd_socket, &mhdr, 0);

	char sbuf[INET6_ADDRSTRLEN], dbuf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, &pkt_info->ipi6_addr, sbuf, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &addr.sin6_addr, dbuf, INET6_ADDRSTRLEN);

	printf("send_raw_icmp[%s->%s] (on if: %d): %s\n", sbuf, dbuf,
			pkt_info->ipi6_ifindex, strerror(errno));
	free (mhdr.msg_control);
}

void * generator_thread() {
	unsigned char icmp_body[2048];
	unsigned int icmp_len = 0;
	int nd_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);

	if (nd_socket < 0) {
		printf("can't create socket(AF_INET6): %s", strerror(errno));
		pthread_exit(0);
	}

	while (1) {
		int i = 0;
		for (i = 0; i < 255; i++) {
			icmp_len = 64;
			memset(icmp_body, 0, sizeof(icmp_body));
			icmp_body[0] = i;

			//printf("send %d\n", i);
			send_raw_icmp(nd_socket, &dest_addr.sin6_addr, icmp_body, icmp_len);
			sleep(2);
		}
	}
}

void *rx_thread() {

	int data_size;
	struct sockaddr_storage clientaddr;
	socklen_t addrlen;
	unsigned char *buffer = (unsigned char *) malloc(65536);
	addrlen = sizeof(clientaddr);

	char clienthost[NI_MAXHOST];
	char clientservice[NI_MAXSERV];
	int nd_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
	struct icmp6_filter filter;
	int err, val;

	if (nd_socket < 0) {
		printf("can't create socket(AF_INET6): %s", strerror(errno));
		pthread_exit(0);
	}

	val = 1;
	err = setsockopt(nd_socket, IPPROTO_IPV6, IPV6_RECVPKTINFO, &val,
			sizeof(val));
	if (err < 0) {
		printf("setsockopt(IPV6_RECVPKTINFO): %s", strerror(errno));
		pthread_exit(0);
	}

	ICMP6_FILTER_SETPASSALL(&filter);

	err = setsockopt(nd_socket, IPPROTO_ICMPV6, ICMP6_FILTER, &filter,
			sizeof(filter));
	if (err < 0) {
		printf("setsockopt(ICMPV6_FILTER): %s", strerror(errno));
		pthread_exit(0);
	}

	//sleep(10);

	while (1) {
		//Receive a packet

		data_size = recvfrom(nd_socket, buffer, 65536, 0,
				(struct sockaddr*) &clientaddr, &addrlen);
		if (data_size < 0) {
			printf("Recvfrom error , failed to get packets\n");
			pthread_exit(0);
		}

		memset(clienthost, 0, sizeof(clienthost));
		memset(clientservice, 0, sizeof(clientservice));

		getnameinfo((struct sockaddr *) &clientaddr, addrlen, clienthost,
				sizeof(clienthost), clientservice, sizeof(clientservice),
				NI_NUMERICHOST);

		printf("recv_raw_icmp[%s->%s]\n", clienthost,"?");

		/*int i;
		for (i = 0; i < data_size; i++) {
			printf("%02x ", buffer[i]);
			if ((i % 16) == 15) {
				printf("\n");
			}
		}*/
		printf("\n");
		//sleep(3);
	}

}

int main(void) {
	pthread_t tid1, tid2;
	struct addrinfo hints, *res;
	int status;

	// Fill out hints for getaddrinfo().
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;

	// Resolve source using getaddrinfo().
	if ((status = getaddrinfo(src_string, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(status));
		return (EXIT_FAILURE);
	}
	memset(&src_addr, 0, sizeof(src_addr));
	memcpy(&src_addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	// Resolve dest using getaddrinfo().
	if ((status = getaddrinfo(dest_string, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(status));
		return (EXIT_FAILURE);
	}
	memset(&dest_addr, 0, sizeof(dest_addr));
	memcpy(&dest_addr, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);

	pthread_create(&tid1, NULL, generator_thread, NULL);
	pthread_create(&tid2, NULL, rx_thread, NULL);

	pthread_join(tid1, NULL);
	pthread_join(tid2, NULL);
	return EXIT_SUCCESS;
}
