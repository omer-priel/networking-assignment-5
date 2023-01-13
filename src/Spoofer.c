#include "api.h"

// IPv4 header len without options
#define IP_HEADER_LEN 20

// ICMP header len for echo req
#define ICMP_HEADER_LEN 8

unsigned short in_cksum(unsigned short *buf, int length)
{
    unsigned short *w = buf;
    int nleft = length;
    int sum = 0;
    unsigned short temp = 0;

    /*
     * The algorithm uses a 32 bit accumulator (sum), adds
     * sequential 16 bit words to it, and at the end, folds back all
     * the carry bits from the top 16 bits into the lower 16 bits.
     */
    while (nleft > 1)
    {
        sum += *w++;
        nleft -= 2;
    }

    /* treat the odd byte at the end, if any */
    if (nleft == 1)
    {
        *(u_char *)(&temp) = *(u_char *)w;
        sum += temp;
    }

    /* add back carry outs from top 16 bits to low 16 bits */
    sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
    sum += (sum >> 16);                 // add carry
    return (unsigned short)(~sum);
}

int main(int argc, char **argv)
{
    char *destination = argv[1];
    char *fake_src = argv[2];

    char packetBuffer[IP_MAXPACKET];

    bzero(packetBuffer, IP_MAXPACKET);
    struct icmpheader *icmp = (struct icmpheader *)(packetBuffer + sizeof(struct ipheader));

    icmp->icmp_type = 8;
    icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                 sizeof(struct icmpheader));

    struct ipheader *ip = (struct ipheader *)packetBuffer;
    ip->iph_ver = 4;
    ip->iph_ihl = 5;
    ip->iph_ttl = 20;
    ip->iph_sourceip.s_addr = inet_addr(fake_src);
    ip->iph_destip.s_addr = inet_addr(destination);
    ip->iph_protocol = IPPROTO_ICMP;
    ip->iph_len = htons(sizeof(struct ipheader) +
                        sizeof(struct icmpheader));

    // Create raw socket for IP-RAW (make IP-header by yourself)
    int sock = -1;

    if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
    {
        printf("ERROR: socket() failed with error: %d\n", errno);
        printf("WARNNING: To create a raw socket, the process needs to be run by Admin/root user.\n");
        return -1;
    }

    int enable = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
               &enable, sizeof(enable));

    struct sockaddr_in dest_in;
    memset(&dest_in, 0, sizeof(struct sockaddr_in));
    dest_in.sin_family = AF_INET;
    dest_in.sin_addr = ip->iph_destip;

    // Send the packet using sendto() for sending datagrams.
    int bytes_sent = sendto(sock, packetBuffer, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_in, sizeof(dest_in));
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
