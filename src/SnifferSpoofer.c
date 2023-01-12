#include "api.h"

int main(int argc, char **argv)
{
    char *filter = "tcp";

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
        return 1;
    }
    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return 1;
    }

    while (1)
    {
        packet = pcap_next(handle, &header);

        printf("P");

        if (header.len > 0)
        {
            struct ethheader *eth = (struct ethheader *)packet;

            printf("eth: %d", eth->ether_type);

            // 0x0800 is IP type
            if (ntohs(eth->ether_type) == 0x0800)
            {
                struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

                printf("IS: %s -> %s", inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));

                if (ip->iph_protocol == IPPROTO_ICMP)
                {
                    struct icmpheader *icmp = (struct icmpheader *)((u_char *)ip + sizeof(struct ipheader));
                    printf("ICMP: %d, %s -> %s", icmp->icmp_type, inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));
                }
            }
        }
    }
}
