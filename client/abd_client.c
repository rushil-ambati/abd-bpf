#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#include "../common/common_abd.h"

#define BUFFER_SIZE 1024

/* Function to send a message and receive a response */
void send_abd_request(const char *server_ip, enum abdmsg_type type, uint32_t tag, uint32_t value, uint32_t counter)
{
    int sockfd;
    struct sockaddr_in6 server_addr;
    struct abdmsg msg, response;
    socklen_t addr_len = sizeof(server_addr);
    ssize_t bytes_received;

    /* Create IPv6 UDP socket */
    if ((sockfd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    /* Set up server IPv6 address */
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin6_family = AF_INET6;
    server_addr.sin6_port = htons(ABD_UDP_PORT);
    if (inet_pton(AF_INET6, server_ip, &server_addr.sin6_addr) <= 0)
    {
        perror("Invalid IPv6 address");
        exit(EXIT_FAILURE);
    }

    /* Prepare ABD message */
    memset(&msg, 0, sizeof(msg));
    msg.type = type;
    msg.tag = tag;
    msg.value = value;
    msg.counter = counter;

    /* Send message */
    if (sendto(sockfd, &msg, sizeof(msg), 0, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        perror("Send failed");
        exit(EXIT_FAILURE);
    }

    printf("Sent %s request to %s\n", (type == ABD_WRITE) ? "WRITE" : "READ", server_ip);

    /* Wait for response */
    bytes_received = recvfrom(sockfd, &response, sizeof(response), 0, (struct sockaddr *)&server_addr, &addr_len);
    if (bytes_received < 0)
    {
        perror("Receive failed");
    }
    else
    {
        // Pretty print the response based on the type
        switch (response.type)
        {
        case ABD_WRITE_ACK:
            printf("Received WRITE_ACK response from %s\n", server_ip);
            break;
        case ABD_READ_ACK:
            printf("Received READ_ACK response from %s: value=%u\n", server_ip, response.value);
            break;
        default:
            printf("Received unknown response from %s\n", server_ip);
            break;
        }
    }

    close(sockfd);
}

/* Main function */
int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        fprintf(stderr, "Usage: %s <server_ip> <write|read> [tag value]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *server_ip = argv[1];
    enum abdmsg_type type;
    uint32_t tag = 0, value = 0, counter = 0;

    if (strcmp(argv[2], "write") == 0)
    {
        if (argc < 6)
        {
            fprintf(stderr, "Usage for write: %s <server_ip> write <tag> <value> <counter>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        type = ABD_WRITE;
        tag = atoi(argv[3]);
        value = atoi(argv[4]);
        counter = atoi(argv[5]);
    }
    else if (strcmp(argv[2], "read") == 0)
    {
        if (argc < 4)
        {
            fprintf(stderr, "Usage for read: %s <server_ip> read <counter>\n", argv[0]);
            exit(EXIT_FAILURE);
        }
        type = ABD_READ;
        counter = atoi(argv[3]);
    }
    else
    {
        fprintf(stderr, "Invalid operation. Use 'write' or 'read'.\n");
        exit(EXIT_FAILURE);
    }

    send_abd_request(server_ip, type, tag, value, counter);
    return 0;
}
