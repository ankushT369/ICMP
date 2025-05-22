/* file: icmp.c */
/* header declaration */
#include "icmp.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/* Macro to print error logs */
#define handle_error(msg) \
        do { perror(msg); exit(EXIT_FAILURE); } while(0)

#define PORT                    8080
#define DEST_MSG                "Hello from destination"

/* Manually compute the checksum for ICMP Packet */
u16 compute_checksum(void* data, size_t length) {
        u32 sum = 0;
        u16* ptr = (u16*)data;

        while (length > 1) {
                sum += *ptr++;
                length -= 2;
        }

        if (length == 1) {
                u16 last_byte = 0;
                *(u8*)&last_byte = *(u8*)ptr;
                sum += last_byte;
        }

        while (sum >> 16)
                sum = (sum & 0xFFFF) + (sum >> 16);

        return ~sum;
}

/* construct the ICMP Header */
void construct_icmp_echo_req(icmp_header* icmp_h, icmp_packet* icmp_p) {
        icmp_h->type            = 8;
        icmp_h->code            = 0;
        icmp_h->identifier      = getpid();
        icmp_h->sequence        = 1;
        icmp_h->checksum        = 0;

        strncpy(icmp_p->payload, DEST_MSG, sizeof(DEST_MSG));

        icmp_p->header.checksum = compute_checksum((void*)icmp_p, sizeof(icmp_header) + strlen(DEST_MSG));
}

int main(int argc, char* argv[]) {
        if (argc < 2) {
                printf("Usage: %s [IP]\n", argv[0]);
                return 1;
        }

        int sockfd;
        struct sockaddr_in dest_addr, recv_addr;
        char recv_buf[1024];
        socklen_t recv_addr_len = sizeof(recv_addr);

        /* initalize the icmp packet*/
        icmp_packet icmp_p;

        /* Create a socket endpoint
         * domaim: AF_INET              purpose: IPv4 Internet protocols
         * type: SOCK_RAW               purpose: Provides raw network protocol access
         * protocol: IPPROTO_ICMP       purpose: Initialise to enable ICMP Protocol
         */
        sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd == -1)
                handle_error("socket");

        /* Set timeval to 3s wait for receiving data if it don't comes exit the program */
        struct timeval timeout = {3, 0};
        setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;

        /* translate the string IP address to network address */
        if (inet_pton(AF_INET, argv[1], &dest_addr.sin_addr) != 1)
                handle_error("inet_pton");

        /* starts constructing the ICMP packet */
        construct_icmp_echo_req(&icmp_p.header, &icmp_p);

        struct timeval start, end;
        /* starts the timer to measure the 1 round trip */
        gettimeofday(&start, NULL);

        /* sends the packet to the destination server */
        if (sendto(sockfd, &icmp_p, sizeof(icmp_header) + strlen(DEST_MSG), 0,
                   (struct sockaddr*)&dest_addr, sizeof(dest_addr)) == -1)
                handle_error("sendto");

        /* recvs the packet from the destination server */
        ssize_t recv_len = recvfrom(sockfd, recv_buf, sizeof(recv_buf), 0,
                                    (struct sockaddr*)&recv_addr, &recv_addr_len);
        /* ends the timer to measure the 1 tip round */
        gettimeofday(&end, NULL);
        if (recv_len == -1)
                handle_error("recvfrom");

        /* calculates the total time for 1 round trip */
        long rtt = (end.tv_sec - start.tv_sec) * 1000 +
                   (end.tv_usec - start.tv_usec) / 1000;

        /* So here's the case when the kernel receives the packet
         * from destination server it adds extra information
         * [IP Header] [ICMP Header] [ICMP Payload (your msg)]
         * ^         ^
         * added by kernel
         * Now below code skips the IP header part which is added by kernel. 
         * Why? I don't know the reason you can search in google 
         */
        int ip_header_len = (recv_buf[0] & 0x0F) * 4;           // IP header skipping part
        icmp_packet* icmp_resp  = (icmp_packet*)(recv_buf + ip_header_len);

        if (icmp_resp->header.type == 0 && icmp_resp->header.identifier == getpid())
                printf("Payload: %.*s, Received ICMP Echo Reply in %ld ms\n",(int)(recv_len - ip_header_len - sizeof(icmp_header)), 
                                icmp_resp->payload, rtt);
        else
                printf("Received non-echo reply. Type: %d, Code: %d\n",
                       icmp_resp->header.type, icmp_resp->header.code);

        return 0;
}

/* tldr :
 * [ICMP Packet sended by my host] -------> network ------> Destination server 
 * [ICMP Packet back to my host  ] <------- network <------ echos back the same packet with same message
 * No TCP/UDP involvement
 */

