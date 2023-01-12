#include "api.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <pcap.h>
#include <stdio.h>
#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>

/* Ethernet header */
struct ethheader
{
    u_char ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};

/* IP Header */
struct ipheader
{
    unsigned char iph_ihl : 4,       // IP header length
        iph_ver : 4;                 // IP version
    unsigned char iph_tos;           // Type of service
    unsigned short int iph_len;      // IP Packet length (data + header)
    unsigned short int iph_ident;    // Identification
    unsigned short int iph_flag : 3, // Fragmentation flags
        iph_offset : 13;             // Flags offset
    unsigned char iph_ttl;           // Time to Live
    unsigned char iph_protocol;      // Protocol type
    unsigned short int iph_chksum;   // IP datagram checksum
    struct in_addr iph_sourceip;     // Source IP address
    struct in_addr iph_destip;       // Destination IP address
};

void got_packet(const struct pcap_pkthdr *header,
                const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;

    if (ntohs(eth->ether_type) == 0x0800)
    { // 0x0800 is IP type
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

        printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("         To: %s\n", inet_ntoa(ip->iph_destip));

        /* determine protocol */
        switch (ip->iph_protocol)
        {
        case IPPROTO_TCP:
            printf("   Protocol: TCP\n");
            return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
        }
    }
}

int main(int argc, char *argv[])
{
    char *filter = argv[1];

    printf("Internet Device: %s\n", NETWORK_DEV);
    printf("Filter: %s\n", filter);

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle;            /* Session handle */
    struct bpf_program fp;     /* The compiled filter expression */
    bpf_u_int32 mask;          /* The netmask of our sniffing device */
    bpf_u_int32 net;           /* The IP of our sniffing device */
    struct pcap_pkthdr header; /* The header that pcap gives us */
    const u_char *packet;      /* The actual packet */

    if (pcap_lookupnet(NETWORK_DEV, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Can't get netmask for device %s\n", NETWORK_DEV);
        net = 0;
        mask = 0;
    }
    handle = pcap_open_live(NETWORK_DEV, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s: %s\n", NETWORK_DEV, errbuf);
        return (2);
    }
    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return (2);
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return (2);
    }

    while (1)
    {
        packet = pcap_next(handle, &header);

        if (header.len > 0)
        {
            got_packet(&header, packet);
        }
    }

    pcap_close(handle);

    return 0;
}
