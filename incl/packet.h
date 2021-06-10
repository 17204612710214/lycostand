/**
 * @file packet.h
 * @brief header of packet processing implementation
 *
 * @author Anonymous
 * @date Mar 30, 2021
*/

#ifndef PACKET_H
#define PACKET_H

#include <stdint.h>
#include <arpa/inet.h>
#include <pcap.h>
#include "running_stats.h"

/* Public API */
/* Ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETH_HEADER 14
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6
typedef struct ethernet_hdr_s {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    uint8_t  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    uint16_t ether_type;                     /* IP? ARP? LLDP? etc */
} ethernet_hdr_t;

/*
 * EtherType according to IANA
 * https://www.iana.org/assignments/ieee-802-numbers/ieee-802-numbers.xhtml
 */
#define ETH_IPv4    0x0800
#define ETH_IPv6    0x86DD
#define ETH_ARP     0x0806
#define ETH_LLDP    0x88CC

/* IP header */
typedef struct ipv4_hdr_s {
    uint8_t  ip_vhl;            /* version << 4 | header length >> 2 */
    uint8_t  ip_tos;            /* type of service */
    uint16_t ip_len;            /* length */
    uint16_t ip_id;             /* identification */
    uint16_t ip_off;            /* fragment offset field */
    uint8_t  ip_ttl;            /* time to live */
    uint8_t  ip_prot;           /* ip_prot */
    uint16_t ip_chksum;         /* checksum */
    uint32_t ip_src;            /* source address */
    uint32_t ip_dst;            /* destination address */
} ipv4_hdr_t;

#define IP_HDR_LEN(ip)  (((ip)->ip_vhl) & 0x0f)
#define IP_VERSION(ip)  (((ip)->ip_vhl) >> 4)

/*
 * IPv4 ip_prot according to IANA
 * https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
 */
#define PROT_ICMP       1
#define PROT_IGMP       2
#define PROT_TCP        6
#define PROT_UDP        17
#define PROT_SCTP       132
#define PROT_UNDEFINED  255

/* IPv4 address format */
typedef struct ipv4_addr_str_s {
    /* allow to get the 4 fields
     * of an IPV4 address, for instance :
     * 192.168.42.1*/
    uint8_t field1;
    uint8_t field2;
    uint8_t field3;
    uint8_t field4;
} ipv4_addr_str_t;

/* IPv6 address format */
typedef struct ipv6_address_s {
    uint16_t addr1;
    uint16_t addr2;
    uint16_t addr3;
    uint16_t addr4;
    uint16_t addr5;
    uint16_t addr6;
    uint16_t addr7;
    uint16_t addr8;
} ipv6_address_t;

/* IPv6 header format */
typedef struct ipv6_hdr_s {
    uint8_t 		byte1;
    uint8_t 		byte2;
    uint8_t 		byte3;
    uint8_t 		byte4;
    uint16_t 		payloadLen;
    uint8_t 		NextHeader;
    uint8_t 		HopLimit;
    ipv6_address_t 	ip_src;
    ipv6_address_t 	ip_dst;
} ipv6_hdr_t;

/* TCP flag values */
#define TCP_FIN     0x01
#define TCP_SYN     0x02
#define TCP_RST     0x04
#define TCP_PSH     0x08
#define TCP_ACK     0x10
#define TCP_URG     0x20
#define TCP_ECE     0x40
#define TCP_CWR     0x80
#define TCP_HDR_LEN(tcp_hdr)  (((tcp_hdr)->data_offset & 0xf0) >> 4)

/* TCP header format */
typedef struct tcp_hdr_s {
    uint16_t src_port;      /* source port */
    uint16_t dst_port;     	/* destination port */
    uint32_t seq_num;       /* sequence number */
    uint32_t ack_num;       /* acknowledgement number */
    uint8_t  data_offset;   /* data offset, rsvd */
    uint8_t  flags;
    uint16_t window;       	/* window */
    uint16_t chksum;       	/* checksum */
    uint16_t urgent_ptr;   	/* urgent pointer */
} tcp_hdr_t;

/* UDP header format */
typedef struct udp_header_s {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t header_lenght;
    uint16_t chksum;
} udp_hdr_t;

/* ICMP header format */
typedef struct icmp_header_s {
    uint8_t type;
    uint8_t code;
    uint16_t chksum;
    uint32_t rest;
} icmp_hdr_t;

/* IGMP header format */
typedef struct igmp_header_s {
    uint8_t  type;
    uint8_t  resp_time;
    uint16_t chksum;
    uint32_t group_addr;
} igmp_hdr_t;

/* SCTP header format */
typedef struct sctp_header_s {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t verif_tag;
    uint32_t chksum;
} sctp_hdr_t;

/* Structure containing packets information */
typedef struct pkt_info_s {
    const uint8_t       *pkt;
    /* packet header*/
    double              *ts;
    uint16_t            pkt_len;
    uint16_t            hdr_len;
    /* headers */
    ethernet_hdr_t   	*eth_hdr;
    union  {
        ipv4_hdr_t   	*ipv4;
        ipv6_hdr_t   	*ipv6;
    };
    union {
        udp_hdr_t    	*udp;
        tcp_hdr_t    	*tcp;
        icmp_hdr_t   	*icmp;
        igmp_hdr_t   	*igmp;
        sctp_hdr_t   	*sctp;
        void            *unknown;
    };
    /* flow ID*/
    union{
        uint32_t 	    *src_ipv4;
        ipv6_address_t	*src_ipv6;
    };
    union{
        uint32_t        *dst_ipv4;
        ipv6_address_t  *dest_ipv6;
    };
    uint16_t            src_port;
    uint16_t            dst_port;
    /*other*/
    uint8_t             ip_prot;
    uint8_t             direction;
    uint16_t            padding[2];
} pkt_info_t;

/* Statistics on packets */
typedef struct pkt_stats_s {
	/* Ethertype statistics */
    uint32_t total;
    uint32_t ipv4;
    uint32_t ipv6;
    uint32_t arp;
    uint32_t lldp;
    uint32_t cdp;
    uint32_t others;
    /* IPv4 protocol statistics */
    uint32_t TCP;
    uint32_t UDP;
    uint32_t ICMP;
    uint32_t IGMP;
    uint32_t SCTP;
    uint32_t otherIPv4;
} pkt_stats_t;

/* TODO: delete all calls to this structure */
typedef struct inter_end_flows_s {
    int32_t         terminated_flow_cnt;
    double          last_flow_ts;
    runstats_data_t stats_inter_end_flows;
} inter_end_flows_t;

void pkt_process(uint8_t *args, const struct pcap_pkthdr *hdr,
                 const uint8_t *pkt);
void pkt_printstats(void);

/* Private API */
#ifdef PACKET_C
void pkt_set_ipv4_info(pkt_info_t *pkt_data, const uint8_t  *pkt,
                       int32_t ipv4_hdr_len);
#endif /* PACKET_C */

#endif /* PACKET_H */
