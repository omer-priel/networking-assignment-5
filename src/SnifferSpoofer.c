#include "api.h"

int counter = 0;

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    if (header->len > 0)
    {
        struct ethheader *eth = (struct ethheader *)packet;

        printf("%d eth: %d\n", counter, eth->ether_type);
        counter++;

        // 0x0800 is IP type
        if (ntohs(eth->ether_type) == 0x0800)
        {
            struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

            printf("IS: %s -> %s\n", inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));

            if (ip->iph_protocol == IPPROTO_ICMP)
            {
                struct icmpheader *icmp = (struct icmpheader *)((u_char *)ip + sizeof(struct ipheader));
                printf("ICMP: %d, %s -> %s\n", icmp->icmp_type, inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));
            }
        }
    }
}

int main(int argc, char **argv)
{
    char filter[] = "icmp";

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle;        /* Session handle */
    struct bpf_program fp; /* The compiled filter expression */
    bpf_u_int32 mask;      /* Our netmask */
    bpf_u_int32 net;       /* The IP of our sniffing device */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
    char *dev = pcap_lookupdev(errbuf);
#pragma GCC diagnostic pop
    if (dev == NULL)
    {
        printf("Couldn't find default device: %s\n", errbuf);
        return 1;
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }

    printf("Internet Device: %s\n", dev);

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL)
    {
        printf("Couldn't open device %s: %s\n", dev, errbuf);
        return 1;
    }
    if (pcap_compile(handle, &fp, filter, 0, net) == -1)
    {
        printf("Couldn't parse filter %s: %s\n", filter, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        printf("Couldn't install filter %s: %s\n", filter, pcap_geterr(handle));
        return 1;
    }

    printf("Start Runing\n");

    pcap_loop(handle, -1, process_packet, NULL);
}
