#include "api.h"

int main(int argc, char *argv[])
{
    printf("Internet Device: %s\n", NETWORK_DEV);

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

        if (header.len > 0)
        {
            struct ethheader *eth = (struct ethheader *)packet;

            // 0x0800 is IP type
            if (ntohs(eth->ether_type) == 0x0800)
            {
                struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));

                if (ip->iph_protocol == IPPROTO_TCP)
                {
                    struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip + sizeof(struct ipheader));
                    struct appheader *app = (struct appheader *)((u_char *)tcp + sizeof(struct tcpheader));
                    char *data = (char *)((char *)app + sizeof(struct appheader));

                    u_char cache_flag = (app->flags % 8) / 4;
                    u_char steps_flag = (app->flags % 4) / 2;
                    u_char type_flag = app->flags % 2;

                    FILE *output = fopen(SNIFFER_OUTPUT, "a");

                    printf("source_ip: %s\n", inet_ntoa(ip->iph_sourceip));
                    printf("dest_ip: %s\n", inet_ntoa(ip->iph_destip));
                    fprintf(output, "{ source_ip: \"%s\", dest_ip: \"%s\"", inet_ntoa(ip->iph_sourceip), inet_ntoa(ip->iph_destip));
                    fprintf(output, ", source_port: %d, source_port: %d", tcp->th_src_port, tcp->th_dst_port);
                    fprintf(output, ", timestamp: %d, total_length: %d", app->timestamp, app->total_length);
                    fprintf(output, ", cache_flag: %d, steps_flag: %d, type_flag: %d", cache_flag, steps_flag, type_flag);
                    fprintf(output, ", status_code: %d, cache_control: %d, data: \"%s\"", app->status_code, app->cache_control, data);
                    fprintf(output, " }\n");

                    fclose(output);
                }
            }
        }
    }

    pcap_close(handle);

    return 0;
}
