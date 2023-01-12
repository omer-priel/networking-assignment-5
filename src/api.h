#pragma once

#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "config.h"

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

/* UDP Header */
struct udpheader
{
    u_int16_t udp_sport; /* source port */
    u_int16_t udp_dport; /* destination port */
    u_int16_t udp_ulen;  /* udp length */
    u_int16_t udp_sum;   /* udp checksum */
};

/* TCP header */
typedef u_int tcp_seq;

struct tcpheader
{
    u_short th_src_port; /* source port */
    u_short th_dst_port; /* destination port */
    tcp_seq th_seq;      /* sequence number */
    tcp_seq th_ack;      /* acknowledgement number */
    u_char th_offx2;     /* data offset, rsvd */
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) > 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win; /* window */
    u_short th_sum; /* checksum */
    u_short th_urp; /* urgent pointer */
};

/* APP header */
struct appheader
{
    u_int timestamp;
    u_short total_length;
    u_char flags;
    u_char status_code;
    u_short cache_control;
    u_short padding;
};

/* ICMP header  */
struct icmpheader
{
    u_char icmp_type;    /* ICMP message type */
    u_char icmp_code;    /* Error code */
    u_short icmp_chksum; /* Checksum for ICMP Header and data */
    u_short icmp_ids;    /* Used for identifying request */
    u_short icmp_seqs;   /* Sequence number */
};

unsigned short calculate_checksum(unsigned short *paddress, int len);
