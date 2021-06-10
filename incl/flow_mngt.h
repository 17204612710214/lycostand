/**
 * @file flow_mngt.h
 * @brief header file for flow management implementation
 * 
 * @author Anonymous
 * @date Mar 30, 2021
*/

#ifndef FLOW_MANAGEMENT_H
#define FLOW_MANAGEMENT_H

#include "singly_linkedlist.h"
#include "feat_calc.h"

/* Public API */
#define FLOW_DIR_FWD              0
#define FLOW_DIR_BWD              1
#define FLOW_TIMEOUT      120000000
#define ACTIVITY_TIMEOUT    5000000
#define TERMINATED_BY_TIMEOUT     2
#define TERMINATED_BY_FLAG        1
#define NOT_TERMINATED            0
/* Maximum segment lifetime */
#define MSL				   60000000
/* Max termination timeout:
 * 1x MSL for FIN_WAIT1, 1x MSL for FIN_WAIT2, 2x MSL for TIME_WAIT
 */
#define TERMINATION_TIMEOUT   4*MSL

typedef sll_node_t flow_node_t;
typedef sll_list_t flow_list_t;

/* Structure containing last forward and backward flow */
typedef struct latest_flow_s {
	flow_data_t *latest_seen;
	flow_data_t *latest_seen_fwd;
	flow_data_t *latest_seen_bwd;
	double latest_closing;
} latest_flow_t;

/* Structure containing elements composing the flow ID */
typedef struct flow_id_s {
    union{
        uint32_t 	    src_IP4;
        ipv6_address_t	src_IP6;
    };
    union{
        uint32_t        dest_IP4;
        ipv6_address_t  dest_IP6;
    };
    uint16_t            src_port;
    uint16_t            dest_port;
    uint16_t            ethertype;
    uint8_t             protocol;
} flow_id_t;

/* Structure containing flow relative statistics */
typedef struct flow_stats_s {
    uint32_t total;
    uint32_t terminated;
} flow_stats_t;

void	    flow_init(latest_flow_t *flow);
int32_t 	flow_cmp_id(flow_data_t *flow_data, pkt_info_t *info);
flow_node_t *flow_search(pkt_info_t *info, flow_list_t *flow_list);
int32_t     flow_add(pkt_info_t *info, flow_list_t *flow_list,
                     latest_flow_t *last_flow);
void 		flow_update(pkt_info_t *info, flow_data_t *flow_data,
                        latest_flow_t *last_flow);
void        print_write_file_header_row(char *filename);
int32_t 	flow_write(flow_data_t *data, char *filename);
int32_t 	flow_final_update(flow_data_t *data, latest_flow_t *last_flow);
int32_t 	flow_check_termination(pkt_info_t *info, flow_node_t *flow);
void        flow_printstats(void);

sll_node_t 	*flow_search_TCP_terminated(pkt_info_t *info, sll_list_t *flow_list);
int32_t 	flow_cmp_TCP_terminated_id(flow_data_TCP_terminated_t *flow_data,
                                    pkt_info_t *info);
int32_t 	flow_cmp_ts_TCP_terminated(flow_data_TCP_terminated_t *flow_data,
                                    double *ts);
void        flow_rm_expired_nodes_TCP_terminated(sll_list_t *flow_list,
                                                 int(*cmp_fn)(void*, void*),
                                                 void *data);

int32_t 	flow_cmp_ts(flow_data_t *flow_data, double *ts);

/* Private API */
#ifdef FLOW_MANAGEMENT_C
void        flow_write_file(flow_data_t *data, char *filename);
#endif /* FLOW_MANAGEMENT_C */

#endif /* FLOW_MANAGEMENT_H */
