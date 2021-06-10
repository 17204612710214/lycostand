/**
 * @file packet.c
 * @brief packet processing
 *
 * @author Anonymous
 * @date Apr 05, 2021
*/

#define PACKET_C

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pcap.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <semaphore.h>
#include "packet.h"
#include "flow_mngt.h"
#include "global_vars.h"

/**
 * @brief callback function to process each received packet
 * @param args pointer to data passed as arguments
 * @param hdr pointer to a structure containing PCAP header
 * @param pkt pointer to the newly received packet
 */
void pkt_process(uint8_t *args, const struct pcap_pkthdr *hdr,
				 const uint8_t *pkt)
{
    pkt_info_t pkt_data; /* information gathered on the received packet */
    pkt_data.pkt = pkt;  /* pointer to the received packet */

    /* Convert packet timestamp to microseconds */
    double micros = ((double)hdr->ts.tv_sec * (double)1000000) +
    				((double)hdr->ts.tv_usec );
    pkt_data.ts = &micros;

    /* Remove IDs from TCP terminated list when all TCP session
     * termination packets are received for these flows
     */
    flow_rm_expired_nodes_TCP_terminated(flow_list_TCP_terminated,
    				(int32_t (*)(void *, void *)) flow_cmp_ts_TCP_terminated,
					 pkt_data.ts);

    /* Pointer to check if a flow corresponding to the
     * packet exists in TCP terminated flow list
     */
    sll_node_t *found_flow_TCP = NULL;

    /* Get ethernet header from packet: */
    flow_node_t *found_flow = NULL;
    pkt_data.eth_hdr = (ethernet_hdr_t*)(pkt);
    pkt_data.hdr_len = 0;
    pkt_stats.total++;
    switch(ntohs(pkt_data.eth_hdr->ether_type)) {
        case ETH_IPv4:
            pkt_stats.ipv4++;
            pkt_data.ipv4 = (ipv4_hdr_t*)(pkt + SIZE_ETH_HEADER);
            int32_t ipv4_hdr_len = IP_HDR_LEN(pkt_data.ipv4) * 4;
            pkt_data.src_ipv4 = &(pkt_data.ipv4->ip_src);
            pkt_data.dst_ipv4 = &(pkt_data.ipv4->ip_dst);
            pkt_data.hdr_len += (uint16_t)(ipv4_hdr_len);
            pkt_data.pkt_len = ntohs(pkt_data.ipv4->ip_len);

            /* Determine protocol associated to IPv4 packet and some features */
            pkt_set_ipv4_info(&pkt_data, pkt, ipv4_hdr_len);

            /* Put relevant packet information for TCP terminated flow list */
            flow_data_TCP_terminated_t data_TCP_terminated;
            data_TCP_terminated.src_ipv4 = *pkt_data.src_ipv4;
            data_TCP_terminated.dst_ipv4 = *pkt_data.dst_ipv4;
            data_TCP_terminated.src_port = pkt_data.src_port;
            data_TCP_terminated.dst_port = pkt_data.dst_port;
            data_TCP_terminated.ip_prot  = pkt_data.ip_prot;
            data_TCP_terminated.last_ts  = *pkt_data.ts;

            /* Completion of basic packet information in pkt_data done!
             * the traffic update, regarding the new packet, starts here: */
            if(pkt_data.ip_prot != PROT_UNDEFINED){
                /* Searching a flow ID corresponding to the
                 * packet in the traffic:
                 */
                found_flow = flow_search(&pkt_data, flow_list_ongoing);

                /* Searching a flow ID corresponding to the
                 * packet in the TCP terminated flow list:
                 */
                found_flow_TCP = flow_search_TCP_terminated(&pkt_data,
                									flow_list_TCP_terminated);
                if(found_flow == NULL) {
                	/* Packet received does not match to any opened flow */
                	if (pkt_data.ip_prot == PROT_TCP && pkt_data.tcp) {
                		/* TCP packet */
						if (found_flow_TCP == NULL) {
							/* flow not in its TCP session termination */
                            if (((pkt_data.tcp->flags & TCP_FIN) == 0) &&
                                ((pkt_data.tcp->flags & TCP_RST) == 0)) {
                            	/* Packet has no closing flag
								 * create new flow:
								 */
								flow_add(&pkt_data, flow_list_ongoing, &latest_flow);
								flow_stats.total++;
							} else {
								/* packet has a closing flag
								 * add flow ID to TCP terminated flow list:
								 */

								/* TODO: cut lines */
								flow_data_TCP_terminated_t *flow_data_TCP_terminated;
								flow_data_TCP_terminated = malloc(sizeof(flow_data_TCP_terminated_t));
								if (flow_data_TCP_terminated == NULL) {
									fprintf(stderr, "[ERROR] pkt_process errno: %d", errno);
									exit(EXIT_FAILURE);
								}
								memcpy(flow_data_TCP_terminated,
									   &data_TCP_terminated,
									   sizeof(flow_data_TCP_terminated_t));
								sll_insert_tail(flow_list_TCP_terminated,
												flow_data_TCP_terminated);
							}
						} else {
							/* flow not in its TCP session termination */
                            if (((pkt_data.tcp->flags & TCP_FIN) == 0) &&
                                ((pkt_data.tcp->flags & TCP_RST) == 0)) {
                            	/* Packet has no closing flag */
								if ((pkt_data.tcp->flags & TCP_SYN) != 0) {
									/* Packet has SYN flag, create new flow: */
									flow_add(&pkt_data,
											 flow_list_ongoing,
											 &latest_flow);
									flow_stats.total++;
                                    /* Remove ID from TCP terminated list */

									/* TODO: cut lines */
									if (sll_remove_node(flow_list_TCP_terminated, found_flow_TCP) == -1) {
										fprintf(stderr, "[ERROR] flow to remove not found\n");
										exit(EXIT_FAILURE);
									}
									/* TODO: keep elses ? */
								} else {
									/* Packet has no SYN flag
									 * discard packet
									 */
								}
							} else {
								/* packet has a closing flag
								 * discard packet
								 */
							}
						}
                	} else {
                		/* other protocol than TCP packet
                		 * create new flow:
                		 */
						flow_add(&pkt_data, flow_list_ongoing, &latest_flow);
						flow_stats.total++;
                	}
                } else {
                	/* Packet received matches with an opened flow */
                    int32_t term_status = flow_check_termination(&pkt_data,
                    											 found_flow);
                    if (term_status == NOT_TERMINATED) {
                    	/* Flow not terminated
                    	 * update flow with packet:
                    	 */
                    	flow_update(&pkt_data, found_flow->data, &latest_flow);
                    } else {
                    	/* Flow terminated */
                        latest_flow.latest_seen = found_flow->data;
                        if (pkt_data.direction == FLOW_DIR_FWD) {
							latest_flow.latest_seen_fwd = found_flow->data;
						} else {
							latest_flow.latest_seen_bwd = found_flow->data;
						}
                        /* allocate memory to copy data from ongoing flow list
                         * to terminated flow list
                         * this avoid double free when node is removed from
                         * ongoing list and terminated list
                         */
                        flow_data_t *data = malloc(sizeof(flow_data_t));
                        if (data == NULL) {
                            fprintf(stderr, "[ERROR] pkt_process errno: %d", errno);
                            exit(EXIT_FAILURE);
                        }
                        memcpy(data, found_flow->data, sizeof(flow_data_t));
                        /* the list of terminated flows is protected by a mutex */
                        pthread_mutex_lock(&mutex);
                        sll_insert_tail(flow_list_terminated, data);
                        pthread_mutex_unlock(&mutex);
                        /* semaphore is used to trigger pthread storing flows */
                        sem_post(&semaphore);
                        /* remove node from list ongoing */
                        if (sll_remove_node(flow_list_ongoing, found_flow) == -1) {
                            fprintf(stderr, "[ERROR] flow to remove not found\n");
                            exit(EXIT_FAILURE);
                        }
                        if (term_status == TERMINATED_BY_TIMEOUT) {
                        	/* flow terminated by a Timeout */
                            if (pkt_data.ip_prot == PROT_TCP && pkt_data.tcp) {
                                /* TCP packet */
                                if (((pkt_data.tcp->flags & TCP_FIN) != 0) ||
                                    ((pkt_data.tcp->flags & TCP_RST) != 0)) {
                                    /* packet has closing flag
                                     * add flow to TCP_terminated list
                                     */

                                	/* TODO: cut lines */
                                    flow_data_TCP_terminated_t *flow_data_TCP_terminated;
                                    flow_data_TCP_terminated = malloc(sizeof(flow_data_TCP_terminated_t));
                                    if (flow_data_TCP_terminated == NULL) {
                                        fprintf(stderr, "[ERROR] pkt_process errno: %d", errno);
                                        exit(EXIT_FAILURE);
                                    }
                                    memcpy(flow_data_TCP_terminated,
                                           &data_TCP_terminated,
                                           sizeof(flow_data_TCP_terminated_t));
                                    sll_insert_tail(flow_list_TCP_terminated,
                                                    flow_data_TCP_terminated);
                                } else {
                                    /* packet has no closing flag */
                                    flow_add(&pkt_data, flow_list_ongoing, &latest_flow);
                                    flow_stats.total++;
                                }
                            } else {
                                /* other protocol than TCP packet */
                                flow_stats.total++;
                                flow_add(&pkt_data, flow_list_ongoing, &latest_flow);
                            }
                        } else {
                        	/* Flow terminated by flag
                        	 * add flow to TCP_terminated list
                        	 */

                        	/* TODO: cut lines */
							flow_data_TCP_terminated_t *flow_data_TCP_terminated;
							flow_data_TCP_terminated = malloc(sizeof(flow_data_TCP_terminated_t));
							if (flow_data_TCP_terminated == NULL) {
								fprintf(stderr, "[ERROR] pkt_process errno: %d", errno);
								exit(EXIT_FAILURE);
							}
							memcpy(flow_data_TCP_terminated,
								   &data_TCP_terminated,
								   sizeof(flow_data_TCP_terminated_t));
							sll_insert_tail(flow_list_TCP_terminated,
											flow_data_TCP_terminated);
                        }
                    }
                }
                /* Display information every 100000 packet to follow the process */
                if ((pkt_stats.total) % (100000) == 0) {
                    pkt_printstats();
                    flow_printstats();
                }
            }
            break;
        case ETH_IPv6:
            pkt_stats.ipv6++;
            break;
        case ETH_LLDP:
            pkt_stats.lldp++;
            break;
        case ETH_ARP:
            pkt_stats.arp++;
            break;
        default: {
            uint32_t dhost_part1;
            dhost_part1 = pkt_data.eth_hdr->ether_dhost[0] << 16 | \
                        pkt_data.eth_hdr->ether_dhost[1] << 8 | \
                        pkt_data.eth_hdr->ether_dhost[2];
            uint32_t dhost_part2;
            dhost_part2 = pkt_data.eth_hdr->ether_dhost[3] << 16 | \
                        pkt_data.eth_hdr->ether_dhost[4] << 8 | \
                        pkt_data.eth_hdr->ether_dhost[5];
            if ((dhost_part1 == 0x01000C) && (dhost_part2 == 0xCCCCCC)) {
                /* CDP: multicast dest MAC address 01:00:0C:CC:CC:CC */
                pkt_stats.cdp++;
            } else {
                pkt_stats.others++;
                fprintf(stderr, "[WARNING] packet type not decoded\n");
            }
        }
            return;
    }
}

/**
 * @brief function to allocate IPv4 protocol in packet information
 * @param pkt_data pointer to structure containing packet information
 * @param pkt pointer to new packet in process
 * @param ipv4_hdr_len length of IPv4 header for the considering packet
 */
void pkt_set_ipv4_info(pkt_info_t *pkt_data, const uint8_t *pkt, int32_t ipv4_hdr_len)
{
	switch(pkt_data->ipv4->ip_prot){
		case PROT_TCP:
			pkt_data->ip_prot = PROT_TCP;
			pkt_data->tcp = (tcp_hdr_t*) (pkt + SIZE_ETH_HEADER + ipv4_hdr_len);
			pkt_data->src_port = ntohs(pkt_data->tcp->src_port);
			pkt_data->dst_port = ntohs(pkt_data->tcp->dst_port);
			int32_t tcp_hdr_len = TCP_HDR_LEN(pkt_data->tcp) * 4;
			pkt_data->hdr_len = (uint16_t) tcp_hdr_len;
			pkt_data->pkt_len -= (ipv4_hdr_len + pkt_data->hdr_len);
			pkt_stats.TCP++;
			break;
		case PROT_UDP:
			pkt_data->ip_prot = PROT_UDP;
			pkt_data->udp = (udp_hdr_t*)(pkt + SIZE_ETH_HEADER + ipv4_hdr_len);
			pkt_data->src_port = ntohs(pkt_data->udp->src_port);
			pkt_data->dst_port = ntohs(pkt_data->udp->dst_port);
			pkt_data->hdr_len = sizeof(udp_hdr_t);
			pkt_data->pkt_len -= (ipv4_hdr_len + pkt_data->hdr_len);
			pkt_stats.UDP++;
			break;
		case PROT_ICMP:
			pkt_data->ip_prot = PROT_ICMP;
			pkt_data->icmp = (icmp_hdr_t*)(pkt + SIZE_ETH_HEADER + ipv4_hdr_len);
			pkt_data->src_port = 0;
			pkt_data->dst_port = 0;
			pkt_data->hdr_len = sizeof(icmp_hdr_t);
			pkt_data->pkt_len -= (ipv4_hdr_len + pkt_data->hdr_len);
			pkt_stats.ICMP++;
			break;
		case PROT_IGMP:
			pkt_data->ip_prot = PROT_IGMP;
			pkt_data->igmp = (igmp_hdr_t*) (pkt + SIZE_ETH_HEADER + ipv4_hdr_len);
			pkt_data->src_port = 0;
			pkt_data->dst_port = 0;
			pkt_data->hdr_len = sizeof(igmp_hdr_t);
			pkt_data->pkt_len -= (ipv4_hdr_len + pkt_data->hdr_len);
			pkt_stats.IGMP++;
			break;
		case PROT_SCTP:
			pkt_data->ip_prot = PROT_SCTP;
			pkt_data->sctp = (sctp_hdr_t*) (pkt + SIZE_ETH_HEADER + ipv4_hdr_len);
			pkt_data->src_port = ntohs(pkt_data->sctp->src_port);
			pkt_data->dst_port = ntohs(pkt_data->sctp->dst_port);
			pkt_data->hdr_len = sizeof(sctp_hdr_t);
			pkt_data->pkt_len -= (ipv4_hdr_len + pkt_data->hdr_len);
			pkt_stats.SCTP++;
			break;
		default:
			pkt_data->ip_prot = PROT_UNDEFINED;
			pkt_data->unknown = (void *) (pkt + SIZE_ETH_HEADER + ipv4_hdr_len);
			pkt_data->src_port = 0;
			pkt_data->dst_port = 0;
			pkt_data->hdr_len = 0;
			pkt_data->pkt_len -= ipv4_hdr_len;
			pkt_stats.otherIPv4++;
	}
}

/**
 * @brief function to display packet statistics
 */
void pkt_printstats(void)
{
    struct timeval tv;
    time_t timestamp;
    struct tm *time_info;
    char buffer[64];
    gettimeofday(&tv, NULL);
    timestamp = tv.tv_sec;
    time_info = localtime( & timestamp );
    strftime (buffer, sizeof(buffer), "%T", time_info);
    printf("-------------------------------------------------------\n");
    printf("%s.%d - ", buffer, (int)(tv.tv_usec / 1000));
    printf("stats on packets :\n");
    printf("\ttotal: \t%d\n", pkt_stats.total);
    printf("\tipv4: \t%d\n", pkt_stats.ipv4);
    printf("\tipv6: \t%d\n", pkt_stats.ipv6);
    printf("\tarp: \t%d\n", pkt_stats.arp);
    printf("\tlldp: \t%d\n", pkt_stats.lldp);
    printf("\tcdp: \t%d\n", pkt_stats.cdp);
    printf("\tothers: %d\n", pkt_stats.others);
    printf("\n");
}

#undef PACKET_C
