#include "api.h"

// IPv4 header len without options
#define IP_HEADER_LEN 20

// ICMP header len for echo req
#define ICMP_HEADER_LEN 8

u_short calculate_checksum(unsigned short *paddress, int len);

int main(int argc, char **argv)
{
    char *destination = argv[1];
    char *fake_src = argv[2];

    int segmentNumber = 0;
    char *data = "THIS IS A PING";
    int size = strlen(data);

    char packetBuffer[IP_MAXPACKET];

    struct icmp header;

    header.icmp_type = ICMP_ECHO;
    header.icmp_code = 0;

    // Identifier (16 bits): some number to trace the response.
    // It will be copied to the response packet and used to map response to the request sent earlier.
    // Thus, it serves as a Transaction-ID when we need to make "ping"
    header.icmp_id = 18;

    header.icmp_seq = segmentNumber;

    header.icmp_cksum = 0;

    // Combine the packet

    // Next, ICMP header
    memcpy((packetBuffer), &header, ICMP_HEADER_LEN);

    // After ICMP header, add the ICMP data.
    memcpy(packetBuffer + ICMP_HEADER_LEN, data, size);

    // Calculate the ICMP header checksum
    header.icmp_cksum = calculate_checksum((unsigned short *)(packetBuffer), ICMP_HEADER_LEN + size);
    memcpy((packetBuffer), &header, ICMP_HEADER_LEN);

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr.s_addr = inet_addr(destination);

    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;

    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
    {
        printf("ERROR: socket() failed with error: %d\n", errno);
        printf("WARNNING: To create a raw socket, the process needs to be run by Admin/root user.\n");
        return -1;
    }

    // Send the packet using sendto() for sending datagrams.
    int bytes_sent = sendto(sock, packetBuffer, ICMP_HEADER_LEN + size, 0, (struct sockaddr *)&dest_in, sizeof(dest_in));
    if (bytes_sent == -1)
    {
        printf("WARNNING: sendto() failed with error: %d\n", errno);
        return -1;
    }

    printf("Ping sented to %s as %s\n", destination, fake_src);

    // Close the raw socket descriptor.
    close(sock);
    return 0;
}
