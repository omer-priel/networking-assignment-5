#include "api.h"

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

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    if (header->len > 0)
    {
        struct ethheader *eth = (struct ethheader *)packet;

        // 0x0800 is IP type
        if (ntohs(eth->ether_type) == 0x0800)
        {
            struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

            if (ip->iph_protocol == IPPROTO_ICMP)
            {
                struct icmpheader *icmp = (struct icmpheader *)((u_char *)ip + sizeof(struct ipheader));

                printf("ICMP: %d, %s", icmp->icmp_type, inet_ntoa(ip->iph_sourceip));
                printf(" -> %s , %d\n", inet_ntoa(ip->iph_destip), icmp->icmp_seqs);

                if (icmp->icmp_type == 8)
                {
                }

                // sendping back
                in_addr_t origin_sourc = ip->iph_sourceip.s_addr;
                in_addr_t origin_dest = ip->iph_destip.s_addr;

                ip->iph_destip.s_addr = origin_sourc;
                ip->iph_sourceip.s_addr = origin_dest;
                icmp->icmp_type = 0;

                int sock = -1;

                if ((sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
                {
                    printf("ERROR: socket() failed with error: %d\n", errno);
                    printf("WARNNING: To create a raw socket, the process needs to be run by Admin/root user.\n");
                }

                int enable = 1;
                setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                           &enable, sizeof(enable));

                struct sockaddr_in dest_in;
                memset(&dest_in, 0, sizeof(struct sockaddr_in));
                dest_in.sin_family = AF_INET;
                dest_in.sin_addr = ip->iph_destip;

                icmp->icmp_chksum = in_cksum((unsigned short *)icmp,
                                             sizeof(struct icmpheader));

                // Send the packet using sendto() for sending datagrams.
                int bytes_sent = sendto(sock, packet, ntohs(ip->iph_len), 0, (struct sockaddr *)&dest_in, sizeof(dest_in));
                if (bytes_sent == -1)
                {
                    printf("WARNNING: sendto() failed with error: %d\n", errno);
                }

                printf("Ping sented to %s", inet_ntoa(ip->iph_sourceip));
                printf(" -> %s\n", inet_ntoa(ip->iph_destip));

                // Close the raw socket descriptor.
                close(sock);
            }
        }
    }
}

int main(int argc, char **argv)
{
    char *dev = argv[1];

    char filter[] = "icmp";

    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *handle;        /* Session handle */
    struct bpf_program fp; /* The compiled filter expression */
    bpf_u_int32 mask;      /* Our netmask */
    bpf_u_int32 net;       /* The IP of our sniffing device */

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
