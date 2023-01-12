#include "api.h"

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

        printf("packet: %s\n", packet);
    }

    pcap_close(handle);

    return 0;
}
