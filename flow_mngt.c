/**
 * @file flow_mngt.c
 * @brief flow management implementation
 *
 * @author Anonymous
 * @date Mar 30, 2021
*/

#define FLOW_MANAGEMENT_C

#include <stdio.h>
#include <netinet/in.h>
#include <time.h>
#include <pthread.h>
#include <stdlib.h>
#include <errno.h>
#include "global_vars.h"
#include "running_stats.h"
#include "packet.h"
#include "flow_mngt.h"

/**
 * @brief Initialize some structures used in flow management
 * @param[in, out] flow pointer to last flow information
 */
void flow_init(latest_flow_t *flow)
{
    flow->latest_seen = NULL;
    flow->latest_seen_fwd = NULL;
    flow->latest_seen_bwd = NULL;
    flow->latest_closing = (double) 0;
}

 /**
  * @brief compare the flow ID of a new packet with the flow ID of an existing
  * flow
  * @param[in] flow_data pointer to structure containing data related to a flow
  * @param[in,out] info pointer to structure containing information related to a
  * new packet
  * @return 0 if flow IDs are identical, -1 otherwise
  * @note flow ID comparison occurs in forward and backward. info structure is
  * updated to reflect the flow direction.
  */
 int32_t flow_cmp_id(flow_data_t *flow_data, pkt_info_t *info)
 {
	if ((info->eth_hdr->ether_type) == 8) {
		if (((flow_data->src_ipv4) == *(info->src_ipv4)) &&
            ((flow_data->dst_ipv4) == *(info->dst_ipv4)) &&
             (flow_data->src_port == info->src_port) &&
             (flow_data->dst_port == info->dst_port)) {
		    /* flow found in forward direction*/
			info->direction = FLOW_DIR_FWD;
			return 0;
		} else if (((flow_data->src_ipv4) == *(info->dst_ipv4)) &&
                   ((flow_data->dst_ipv4) == *(info->src_ipv4)) &&
                    (flow_data->src_port == info->dst_port) &&
                    (flow_data->dst_port == info->src_port)) {
		    /* flow found in backward direction */
			info->direction = FLOW_DIR_BWD;
            return 0;
        } else {
        	/* flow not found: to be added in forward direction
			 * ! order correction: if first packet contains SYN and ACK
			 * it means that the 2 firsts packets are reversed!
			 */
        	if (((info->tcp->flags & TCP_SYN) != 0) &&
        		((info->tcp->flags & TCP_ACK) != 0)) {
				info->direction = FLOW_DIR_BWD;
			} else {
				info->direction = FLOW_DIR_FWD;
			}
			return -1;
        }
	} else {
//        fprintf(stderr, "[WARNING] flow processing only supports IPv4\n");
        return -1;
    }
}

/**
 * @brief Search if the flow already exists in the list passed as argument
 * @param[in, out] info pointer to structure containing information related to a
 * new packet
 * @param[in] flow_list pointer to list of flows in which flow corresponding to
 * the new packet has to be searched
 * @return pointer to the node if the flow is found, NULL otherwise
 */
flow_node_t *flow_search(pkt_info_t *info, flow_list_t *flow_list)
{
	flow_node_t *found_flow = NULL;
	found_flow = sll_find(flow_list,
						   (int32_t (*)(void *, void *)) flow_cmp_id,
						   info);
	/* note: packet direction is set in flow_cmp_id */
	return found_flow;
}

/**
 * @brief Add a flow to the list of existing flows
 * @param info pointer to structure containing information related to a
 * new packet
 * @param flow_list pointer to list of flows in which flow corresponding to
 * the new packet has to be added
 * @param[in, out] last_flow pointer to structure containing pointer to last flows in
 * forward and backward directions
 * @return 0 when finished or -1 if an error occurred
 */
int32_t flow_add(pkt_info_t *info, flow_list_t *flow_list,
                 latest_flow_t *last_flow)
{
	/* Complete the fields of the new flow to add to flow_list: */
	flow_data_t *data;
	data = malloc(sizeof(flow_data_t));
    if (data == NULL) {
        fprintf(stderr, "[ERROR] flow_add errno: %d", errno);
    }

    /* Check direction in case of a timeout or reversion of two firsts packets */
	if (info->direction == FLOW_DIR_FWD) {
		if((info->eth_hdr->ether_type) == ntohs(ETH_IPv4)) {
			data->src_ipv4 = *(info->src_ipv4);
			data->dst_ipv4 = *(info->dst_ipv4);
		} else {
//        	fprintf(stderr, "[WARNING] flow processing only supports IPv4\n");
			return -1;
		}
		data->src_port = info->src_port;
		data->dst_port = info->dst_port;
		data->last_fwd_ts = *info->ts;
		/* Initialization of the flow features in forward: */
		data->feat = featcalc_init_feat_fwd(info);
	} else {
		if((info->eth_hdr->ether_type) == ntohs(ETH_IPv4)) {
			data->src_ipv4 = *(info->dst_ipv4);
			data->dst_ipv4 = *(info->src_ipv4);
		} else {
//        	fprintf(stderr, "[WARNING] flow processing only supports IPv4\n");
			return -1;
		}
		data->src_port = info->dst_port;
		data->dst_port = info->src_port;
		data->last_bwd_ts = *info->ts;
		/* Initialization of the flow features in backward: */
		data->feat = featcalc_init_feat_bwd(info);
	}
	data->first_ts = *info->ts;
	data->last_ts = *info->ts;
	data->beg_act_us = *info->ts;
	runstats_rst(&(data->feat.active));
	runstats_rst(&(data->feat.idle));
	data->feat.active.n_elements = 0;
	data->feat.idle.n_elements = 0;
	/* Bulk variables initialization: */
	featcalc_init_bulk(&(data->bulk));
	data->ip_version = info->eth_hdr->ether_type;
	data->subflow_cnt = 1;
	featcalc_update_bulk(info, data);
	if((info->eth_hdr->ether_type) == 8) {
        data->ip_prot = info->ipv4->ip_prot;
	} else {
//        fprintf(stderr, "[WARNING] flow processing only supports IPv4\n");
        return -1;
    }
    /* Add a new flow to existing flow_list: */
    sll_insert_tail(flow_list, data);
    last_flow->latest_seen = data;
    if (info->direction == FLOW_DIR_FWD) {
		last_flow->latest_seen_fwd = data;
    } else {
    	last_flow->latest_seen_bwd = data;
    }
    return 0;
}

/**
 * @brief Update all flow characteristics with new packet information
 * @param[in] info pointer to structure containing information related to a
 * new packet
 * @param[in,out] flow_data pointer to structure containing data related to a flow
 * @param[in,out] last_flow pointer to structure containing data related to
 * the traffic
 */
void flow_update(pkt_info_t *info, flow_data_t *flow_data,
                 latest_flow_t *last_flow)
{
	feat_update_timestamps_t feat_update_ts;
    feat_update_ts.last_flow_ts = flow_data->last_ts;
    feat_update_ts.last_flow_fwd_ts = flow_data->last_fwd_ts;
    feat_update_ts.last_flow_bwd_ts = flow_data->last_bwd_ts;
	/* Update the flow features with data from new packet: */
    featcalc_update(&flow_data->feat, info, feat_update_ts);
    featcalc_update_active_idle(&flow_data->feat, info, feat_update_ts,
                                &flow_data->beg_act_us,
                                ACTIVITY_TIMEOUT);
	/* 
	 * Update useful information for IAT, active and idle
	 * (info on former timestamps and flows):
	 */
	featcalc_update_bulk(info, flow_data);
    featcalc_update_subflow_cnt(flow_data, *info->ts, flow_data->last_ts);
	flow_data->last_ts = *info->ts;
    last_flow->latest_seen = flow_data;
	if (info->direction == FLOW_DIR_FWD) {
		flow_data->last_fwd_ts = *info->ts;
        last_flow->latest_seen_fwd = flow_data;
	} else {
		flow_data->last_bwd_ts = *info->ts;
        last_flow->latest_seen_bwd = flow_data;
	}
}

/**
 * @brief Write first row of CSV file containing column names
 * @param[in] filename pointer to a string containing the filename
 */
void print_write_file_header_row(char *filename)
{
    FILE *fp;
	fp = fopen(filename, "w");
    fprintf(fp, "flow_id,src_addr,src_port,dst_addr,dst_port,ip_prot,timestamp,"
                "flow_duration,down_up_ratio,pkt_len_max,pkt_len_min,"
                "pkt_len_mean,pkt_len_var,pkt_len_std,bytes_per_s,pkt_per_s,"
                "fwd_pkt_per_s,bwd_pkt_per_s,fwd_pkt_cnt,fwd_pkt_len_tot,"
                "fwd_pkt_len_max,fwd_pkt_len_min,fwd_pkt_len_mean,"
                "fwd_pkt_len_std,fwd_pkt_hdr_len_tot,fwd_pkt_hdr_len_min,"
                "fwd_non_empty_pkt_cnt,bwd_pkt_cnt,bwd_pkt_len_tot,"
                "bwd_pkt_len_max,bwd_pkt_len_min,bwd_pkt_len_mean,"
                "bwd_pkt_len_std,bwd_pkt_hdr_len_tot,bwd_pkt_hdr_len_min,"
                "bwd_non_empty_pkt_cnt,iat_max,iat_min,iat_mean,iat_std,"
                "fwd_iat_tot,fwd_iat_max,fwd_iat_min,fwd_iat_mean,"
                "fwd_iat_std,bwd_iat_tot,bwd_iat_max,bwd_iat_min,"
                "bwd_iat_mean,bwd_iat_std,active_max,active_min,active_mean,"
                "active_std,idle_max,idle_min,idle_mean,idle_std,flag_SYN,"
                "flag_fin,flag_rst,flag_ack,flag_psh,fwd_flag_psh,bwd_flag_psh,"
                "flag_urg,fwd_flag_urg,bwd_flag_urg,flag_cwr,flag_ece,"
                "fwd_bulk_bytes_mean,fwd_bulk_pkt_mean,fwd_bulk_rate_mean,"
                "bwd_bulk_bytes_mean,bwd_bulk_pkt_mean,bwd_bulk_rate_mean,"
                "fwd_subflow_bytes_mean,fwd_subflow_pkt_mean,"
                "bwd_subflow_bytes_mean,bwd_subflow_pkt_mean,"
                "fwd_tcp_init_win_bytes,bwd_tcp_init_win_bytes,"
                "label\n");
    fclose(fp);
}

/**
 * @brief Write features into a file
 * @param[in] data pointer to structure containing data of the flow to write
 * @param[in] filename pointer to a string containing the filename
 */
void flow_write_file(flow_data_t *data, char *filename)
{
    FILE *fp = fopen(filename, "a");
	if(data->ip_version == 8) {
		ipv4_addr_str_t *src_struct_ipv4_addr;
		ipv4_addr_str_t *dest_struct_ipv4_addr;
		src_struct_ipv4_addr = (ipv4_addr_str_t*) (&data->src_ipv4);
		dest_struct_ipv4_addr = (ipv4_addr_str_t*) (&data->dst_ipv4);
		fprintf(fp, "%d.%d.%d.%d-%d.%d.%d.%d-%u-%u-%u,", 					/* 1 flow_id */
                (int)(src_struct_ipv4_addr->field1),
                (int)(src_struct_ipv4_addr->field2),
                (int)(src_struct_ipv4_addr->field3),
                (int)(src_struct_ipv4_addr->field4),
                (int)(dest_struct_ipv4_addr->field1),
                (int)(dest_struct_ipv4_addr->field2),
                (int)(dest_struct_ipv4_addr->field3),
                (int)(dest_struct_ipv4_addr->field4),
                data->src_port,
                data->dst_port,
                data->ip_prot);
		fprintf(fp, "%d.%d.%d.%d,",(int)(src_struct_ipv4_addr->field1), 	/* 2 src_addr */
								   (int)(src_struct_ipv4_addr->field2),
								   (int)(src_struct_ipv4_addr->field3),
								   (int)(src_struct_ipv4_addr->field4));
		fprintf(fp, "%u,", data->src_port); 								/* 3 src_port */
		fprintf(fp, "%d.%d.%d.%d,",(int)(dest_struct_ipv4_addr->field1), 	/* 4 dst_addr */
								   (int)(dest_struct_ipv4_addr->field2),
								   (int)(dest_struct_ipv4_addr->field3),
								   (int)(dest_struct_ipv4_addr->field4));
		fprintf(fp, "%u,", data->dst_port); 								/* 5 dst_port */
	} else {
//        fprintf(stderr, "[WARNING] flow processing only supports IPv4\n");
	}
	fprintf(fp, "%u,", data->ip_prot); 										/* 6 ip_prot */
    fprintf(fp, "%lu,",(int64_t)(data->first_ts)); 			                /* 7 timestamp */
	fprintf(fp, "%li,",(int64_t)(data->feat.flow_duration_us)); 			/* 8 flow_duration */
	fprintf(fp, "%lf,", data->feat.down_up_ratio); 							/* 9 down_up_ratio */
    fprintf(fp, "%lf,", runstats_get_max(&data->feat.len_pkt_stats)); 		/* 10 pkt_len_max */
	fprintf(fp, "%lf,", runstats_get_min(&data->feat.len_pkt_stats)); 		/* 11 pkt_len_min */
    fprintf(fp, "%lf,", runstats_get_mean(&data->feat.len_pkt_stats)); 		/* 12 pkt_len_mean */
    fprintf(fp, "%lf,", runstats_get_var(&data->feat.len_pkt_stats)); 		/* 13 pkt_len_var */
    fprintf(fp, "%lf,", runstats_get_std(&data->feat.len_pkt_stats)); 		/* 14 pkt_len_std */
	fprintf(fp, "%lf,", data->feat.bytes_per_s); 							/* 15 bytes_per_s */
	fprintf(fp, "%lf,", data->feat.pkt_per_s); 								/* 16 pkt_per_s */
	fprintf(fp, "%lf,", data->feat.fwd_pkt_per_s); 							/* 17 fwd_pkt_per_s*/
	fprintf(fp, "%lf,", data->feat.bwd_pkt_per_s);							/* 18 bwd_pkt_per_s*/
	fprintf(fp, "%d,", data->feat.total_fwd_pkt); 							/* 19 fwd_pkt_cnt */
	fprintf(fp, "%li,", runstats_get_sum(&data->feat.fwd_len_pkt_stats)); 	/* 20 fwd_pkt_len_tot */
	fprintf(fp, "%lf,", runstats_get_max(&data->feat.fwd_len_pkt_stats)); 	/* 21 fwd_pkt_len_max */
	fprintf(fp, "%lf,", runstats_get_min(&data->feat.fwd_len_pkt_stats)); 	/* 22 fwd_pkt_len_min */
	fprintf(fp, "%lf,", runstats_get_mean(&data->feat.fwd_len_pkt_stats)); 	/* 23 fwd_pkt_len_mean */
	fprintf(fp, "%lf,", runstats_get_std(&data->feat.fwd_len_pkt_stats)); 	/* 24 fwd_pkt_len_std */
	fprintf(fp, "%u,", data->feat.fwd_hdr_len); 							/* 25 fwd_pkt_hdr_len_tot */
	fprintf(fp, "%u,", data->feat.fwd_hdr_len_min); 						/* 26 fwd_pkt_hdr_len_min */
	fprintf(fp, "%u,", data->feat.fwd_non_empty_pkt_cnt); 					/* 27 fwd_non_empty_pkt_cnt */
	fprintf(fp, "%d,", data->feat.total_bwd_pkt); 							/* 28 bwd_pkt_cnt */
	fprintf(fp, "%li,", runstats_get_sum(&data->feat.bwd_len_pkt_stats));   /* 29 bwd_pkt_len_tot */
	fprintf(fp, "%lf,", runstats_get_max(&data->feat.bwd_len_pkt_stats)); 	/* 30 bwd_pkt_len_max */
	fprintf(fp, "%lf,", runstats_get_min(&data->feat.bwd_len_pkt_stats)); 	/* 31 bwd_pkt_len_min */
	fprintf(fp, "%lf,", runstats_get_mean(&data->feat.bwd_len_pkt_stats)); 	/* 32 bwd_pkt_len_mean */
	fprintf(fp, "%lf,", runstats_get_std(&data->feat.bwd_len_pkt_stats)); 	/* 33 bwd_pkt_len_std */
	fprintf(fp, "%u,", data->feat.bwd_hdr_len); 							/* 34 bwd_pkt_hdr_len_tot */
	fprintf(fp, "%u,", data->feat.bwd_hdr_len_min);							/* 35 bwd_pkt_hdr_len_min */
	fprintf(fp, "%u,", data->feat.bwd_non_empty_pkt_cnt);					/* 36 bwd_non_empty_pkt_cnt */
	fprintf(fp, "%lf,", runstats_get_max(&data->feat.iat_stats)); 			/* 37 IAT_max */
	fprintf(fp, "%lf,", runstats_get_min(&data->feat.iat_stats)); 			/* 38 IAT_min */
	fprintf(fp, "%lf,", runstats_get_mean(&data->feat.iat_stats)); 			/* 39 IAT_mean */
	fprintf(fp, "%lf,", runstats_get_std(&data->feat.iat_stats)); 			/* 40 IAT_std */
	fprintf(fp, "%li,", runstats_get_sum(&data->feat.fwd_iat_stats)); 		/* 41 fwd_IAT_tot */
	fprintf(fp, "%lf,", runstats_get_max(&data->feat.fwd_iat_stats)); 		/* 42 fwd_IAT_max */
	fprintf(fp, "%lf,", runstats_get_min(&data->feat.fwd_iat_stats)); 		/* 43 fwd_IAT_min */
	fprintf(fp, "%lf,", runstats_get_mean(&data->feat.fwd_iat_stats)); 		/* 44 fwd_IAT_mean */
	fprintf(fp, "%lf,", runstats_get_std(&data->feat.fwd_iat_stats)); 		/* 45 fwd_IAT_std */
	fprintf(fp, "%li,", runstats_get_sum(&data->feat.bwd_iat_stats)); 		/* 46 bwd_IAT_tot */
	fprintf(fp, "%lf,", runstats_get_max(&data->feat.bwd_iat_stats)); 		/* 47 bwd_IAT_max */
	fprintf(fp, "%lf,", runstats_get_min(&data->feat.bwd_iat_stats)); 		/* 48 bwd_IAT_min */
	fprintf(fp, "%lf,", runstats_get_mean(&data->feat.bwd_iat_stats)); 		/* 49 bwd_IAT_mean */
	fprintf(fp, "%lf,", runstats_get_std(&data->feat.bwd_iat_stats)); 		/* 50 bwd_IAT_std */
	fprintf(fp, "%lf,", runstats_get_max(&data->feat.active)); 				/* 51 active_max */
	fprintf(fp, "%lf,", runstats_get_min(&data->feat.active)); 				/* 52 active_min */
	fprintf(fp, "%lf,", runstats_get_mean(&data->feat.active)); 			/* 53 active_mean */
	fprintf(fp, "%lf,", runstats_get_std(&data->feat.active));   			/* 54 active_std */
	fprintf(fp, "%lf,", runstats_get_max(&data->feat.idle)); 				/* 55 idle_max */
	fprintf(fp, "%lf,", runstats_get_min(&data->feat.idle)); 				/* 56 idle_min */
	fprintf(fp, "%lf,", runstats_get_mean(&data->feat.idle)); 				/* 57 idle_mean */
	fprintf(fp, "%lf,", runstats_get_std(&data->feat.idle)); 				/* 58 idle_std */
	fprintf(fp, "%u,", data->feat.syn_flag_cnt); 							/* 59 flag_SYN */
	fprintf(fp, "%u,", data->feat.fin_flag_cnt); 							/* 60 flag_FIN */
	fprintf(fp, "%u,", data->feat.rst_flag_cnt); 							/* 61 flag_RST */
	fprintf(fp, "%u,", data->feat.ack_flag_cnt); 							/* 62 flag_ACK */
	fprintf(fp, "%u,", data->feat.psh_flag_cnt); 							/* 63 flag_PSH */
	fprintf(fp, "%u,", data->feat.fwd_psh_flag_cnt);						/* 64 fwd_flag_PSH */
	fprintf(fp, "%u,", data->feat.bwd_psh_flag_cnt);  						/* 65 bwd_flag_PSH */
	fprintf(fp, "%u,", data->feat.urg_flag_cnt); 							/* 66 flag_URG */
	fprintf(fp, "%u,", data->feat.fwd_urg_flag_cnt); 						/* 67 fwd_flag_URG */
	fprintf(fp, "%u,", data->feat.bwd_urg_flag_cnt); 						/* 68 bwd_flag_URG */
	fprintf(fp, "%u,", data->feat.cwr_flag_cnt); 							/* 69 flag_CWR */
	fprintf(fp, "%u,", data->feat.ece_flag_cnt); 							/* 70 flag_ECE */
	fprintf(fp, "%lf,", data->feat.fwd_bytes_per_bulk_mean); 				/* 71 fwd_bulk_bytes_mean */
	fprintf(fp, "%lf,", data->feat.fwd_pkt_per_bulk_mean); 					/* 72 fwd_bulk_pkt_mean */
	fprintf(fp, "%lf,", data->feat.fwd_bulk_rate_mean);  					/* 73 fwd_bulk_rate_mean */
	fprintf(fp, "%lf,", data->feat.bwd_bytes_per_bulk_mean); 				/* 74 bwd_bulk_bytes_mean */
	fprintf(fp, "%lf, ", data->feat.bwd_pkt_per_bulk_mean); 				/* 75 bwd_bulk_pkt_mean */
	fprintf(fp, "%lf,", data->feat.bwd_bulk_rate_mean); 					/* 76 bwd_bulk_rate_mean */
	fprintf(fp, "%lf,",data->feat.fwd_subflow_bytes); 						/* 77 fwd_subflow_bytes_mean */
	fprintf(fp, "%lf,",data->feat.fwd_subflow_pkt); 						/* 78 fwd_subflow_pkt_mean */
	fprintf(fp, "%lf,",data->feat.bwd_subflow_bytes); 						/* 79 bwd_subflow_bytes_mean */
	fprintf(fp, "%lf,",data->feat.bwd_subflow_pkt); 						/* 80 bwd_subflow_pkt_mean */
	if (data->ip_prot == PROT_TCP) {
		fprintf(fp, "%u,", data->feat.fwd_init_win_bytes); 					/* 81 fwd_TCP_init_win_bytes */
	} else {

		fprintf(fp, "-1,"); 												/* 81 fwd_TCP_init_win_bytes */
	}
	if(data->ip_prot == PROT_TCP && data->feat.total_bwd_pkt != 0 ){
		fprintf(fp, "%u,", data->feat.bwd_init_win_bytes); 					/* 82 bwd_TCP_init_win_bytes */
	}
	else{

		fprintf(fp, "-1,"); 												/* 82 bwd_TCP_init_win_bytes */
	}
	fprintf(fp, "NeedLabel\n");
    fclose(fp);
}

/**
 * @brief Write features of a given flow in a file
 * @param[in] data structure containing data of the flow to write
 * @param[in] fp file pointer
 * @return always 0
 * @note a compiler switch allows printing of features to stdout
 */
int32_t flow_write(flow_data_t *data, char *filename)
{
    flow_write_file(data, filename);
    flow_stats.terminated++;
    return 0; 
	
}


/**
 * @brief This function updates one last time the features of the data before
 * closing them, taking the last packet timestamp received as current time
 * reference (end of reception).
 * @param data pointer to structure containing flow data
 * @param last_flow pointer to structure containing data from the last flow
 * @return always 0
 * @note This function is used for flows not ended during reception (UDP or
 * TCP flows that didn't get FIN or RST flag)
 */
int32_t flow_final_update(flow_data_t *data, latest_flow_t *last_flow)
{
	double ts_diff = last_flow->latest_seen->last_ts - data->first_ts;
	if(ts_diff >= FLOW_TIMEOUT){
        featcalc_endOfFlow_update(&data->feat, data->bulk, data->subflow_cnt);
        /* Allocate memory to copy data from ongoing flow list to terminated
         * flow list, this avoid double free when node is removed from ongoing
         * list and terminated list
         */
        flow_data_t *flow_data = malloc(sizeof(flow_data_t));
        if (flow_data == NULL) {
            fprintf(stderr, "[ERROR] flow_final_update errno: %d", errno);
            exit(EXIT_FAILURE);
        }
        memcpy(flow_data, data, sizeof(flow_data_t));
        /* The terminated flow list is protected by a mutex */
        pthread_mutex_lock(&mutex);
        sll_insert_tail(flow_list_terminated, flow_data);
        /* Semaphore is used to trigger pthread storing flows */
        sem_post(&semaphore);
        pthread_mutex_unlock(&mutex);
	}
	return 0;
}

/**
 * @brief Check if the flow corresponding to the received packet reached the
 * Timeout or if a closing flag (FIN or RST) is in the new packet
 * @param[in] info pointer to structure containing information related to a
 * new packet
 * @param[in] flow pointer to the flow corresponding to the new packet
 * @return terminated status:
 * NOT_TERMINATED, TERMINATED_BY_TIMEOUT, TERMINATED_BY_FLAG
 */
int32_t flow_check_termination(pkt_info_t *info, flow_node_t *flow)
{
	feat_update_timestamps_t featUpdteTimestmps;
	featUpdteTimestmps.last_flow_ts = ((flow_data_t*)flow->data )->last_ts;
	featUpdteTimestmps.last_flow_fwd_ts = ((flow_data_t*)flow->data )->last_fwd_ts;
	featUpdteTimestmps.last_flow_bwd_ts = ((flow_data_t*)flow->data )->last_bwd_ts;
	double duration = featcalc_update_duration(info,
                                          ((flow_data_t*) flow->data)->first_ts);
	if (duration >= FLOW_TIMEOUT) {
		/* End of flow by timeout: */
        featcalc_endOfFlow_update(&((flow_data_t *) flow->data)->feat,
                                   ((flow_data_t *) flow->data)->bulk,
                                   ((flow_data_t *) flow->data)->subflow_cnt);
		if (((flow_data_t*)flow->data)->feat.active.n_elements == 0) {
			((flow_data_t*)flow->data)->feat.active = runstats_init(0);
		}
		if (((flow_data_t*)flow->data)->feat.idle.n_elements == 0) {
			((flow_data_t*)flow->data)->feat.idle= runstats_init(0);
		}
		return TERMINATED_BY_TIMEOUT ;
	} else if (info->ip_prot == PROT_TCP && info->tcp) {
		((flow_data_t*)flow->data)->feat.flow_duration_us = duration;
		if ((((info->tcp->flags) & TCP_FIN ) != 0) ||
			(((info->tcp->flags) & TCP_RST ) != 0)) {
			/* End of flow by flag: */
			featcalc_update_bulk(info, ((flow_data_t*)flow->data ));
            featcalc_update(&((flow_data_t*) flow->data)->feat, info,
							featUpdteTimestmps);
            featcalc_update_subflow_cnt(((flow_data_t *) flow->data), *info->ts,
                                        ((flow_data_t *) flow->data)->last_ts);
            featcalc_endOfFlow_update(&((flow_data_t *) flow->data)->feat,
                                       ((flow_data_t *) flow->data)->bulk,
                                       ((flow_data_t *) flow->data)->subflow_cnt);
			if (((flow_data_t*) flow->data)->feat.active.n_elements == 0) {
				((flow_data_t*)flow->data)->feat.active = runstats_init(0);
			}
			if (((flow_data_t*)flow->data)->feat.idle.n_elements == 0) {
				((flow_data_t*)flow->data)->feat.idle = runstats_init(0);
			}
			return TERMINATED_BY_FLAG ;
		} else {
			return NOT_TERMINATED ;
		}
	} else {
	    /* Other protocol than TCP packet */
		((flow_data_t*)flow->data)->feat.flow_duration_us = duration;
		return NOT_TERMINATED ;
    }
}

/**
 * @brief Print flow statistics in console
 */
void flow_printstats(void)
{
    printf("stats on flow :\n");
    printf("\tflow_list_ongoing.length = \t%d\n", flow_list_ongoing->length);
    printf("\tflow_list_ongoing.max_length = \t%d\n", flow_list_ongoing->max_length);
    printf("\tflow_list_terminated.length = \t%d\n", flow_list_terminated->length);
    printf("\tflow_list_terminated.max_length = %d\n", flow_list_terminated->max_length);
    printf("\ttotal: \t\t%d\n", flow_stats.total);
    printf("\tterminated: \t%d\n", flow_stats.terminated);
}

/**
 * Compare difference between packet timestamp and first flow timestamp
 * with FLOW_TIMEOUT
 * @param flow_data pointer to structure containing data related to a flow
 * @param info pointer to structure containing information related to a
 * new packet
 * @return 0 if the timestamp difference is equal to FLOW_TIMEOUT,
  * 1 if the timestamp difference is greater than FLOW_TIMEOUT,
  * -1 otherwise
 */
int32_t flow_cmp_ts(flow_data_t *flow_data, double *ts)
{
    if (*ts-(flow_data->first_ts) == FLOW_TIMEOUT) {
        return 0;
    } else if (*ts-(flow_data->first_ts) > FLOW_TIMEOUT) {
        return 1;
    } else {
        return -1;
    }
}

/**
  * @brief Compare the flow ID of a new packet with the flow ID of a
  * TCP terminated flow
  * @param[in] flow_data pointer to structure containing data related to a flow
  * @param[in,out] info pointer to structure containing information related to a
  * new packet
  * @return 0 if flow IDs are identical, -1 otherwise
  * @note flow ID comparison occurs in forward and backward. info structure is
  * updated to reflect the flow direction.
  */
int32_t flow_cmp_TCP_terminated_id(flow_data_TCP_terminated_t *flow_data, pkt_info_t *info)
{
	if ((flow_data->src_ipv4 == *(info->src_ipv4)) &&
		(flow_data->dst_ipv4 == *(info->dst_ipv4)) &&
		(flow_data->src_port == info->src_port) &&
		(flow_data->dst_port == info->dst_port)) {
		return 0;
	} else if ((flow_data->src_ipv4 == *(info->dst_ipv4)) &&
			   (flow_data->dst_ipv4 == *(info->src_ipv4)) &&
			   (flow_data->src_port == info->dst_port) &&
			   (flow_data->dst_port == info->src_port)) {
		return 0;
	} else {
		return -1;
	}
}

/**
 * @brief Check if nodes have reached TERMINATION_TIMEOUT
 * @param[in] flow_data pointer to structure containing data related to a node
 * @param[in] ts pointer to the current packet timestamp
 * @return 0 if the timestamp difference is equal to TERMINATION_TIMEOUT,
 * 1 if the timestamp difference is greater than TERMINATION_TIMEOUT,
 * -1 otherwise
 */
int32_t flow_cmp_ts_TCP_terminated(flow_data_TCP_terminated_t *flow_data, double *ts)
{
	if (*ts-(flow_data->last_ts) == TERMINATION_TIMEOUT) {
		return 0;
	} else if (*ts-(flow_data->last_ts) > TERMINATION_TIMEOUT) {
		return 1;
	} else {
		return -1;
	}
}

/**
 * @brief Search if the flow already exists in the TCP terminated flow list
 * @param[in] info pointer to structure containing information related to a
 * new packet
 * @param[in] flow_list pointer to flow list in which flow corresponding to the
 * new packet has to be searched
 * @return pointer to the node if the flow is found, NULL otherwise
 */
sll_node_t *flow_search_TCP_terminated(pkt_info_t *info, sll_list_t *flow_list)
{
	sll_node_t *found_flow = NULL;
	found_flow = sll_find(flow_list,
				(int32_t (*)(void *, void *)) flow_cmp_TCP_terminated_id, info);

	return found_flow;
}

/**
 * @brief Remove nodes if the TERMINATION_TIMEOUT is reached
 * @param[in] flow_list pointer to flow list in which flow corresponding to the
 * new packet has to be searched
 * @param[in] cmp_fn comparison function to check if the TERMINATION_TIMEOUT is
 * reached
 * @param data pointer to the current packet data to use its timestamp in
 * the comparison function
 */
void flow_rm_expired_nodes_TCP_terminated(sll_list_t *flow_list,
		 	 	 	 	 	 	 	 int(*cmp_fn)(void*, void*), void *data)
{
	sll_node_t *node;
    if (flow_list != NULL) {
        node = flow_list->head;
        while (node) {
            /* comparison function is expected to  *
             * return -1 if condition is unreached */
            if (cmp_fn(node->data, data) != -1) {
                if (sll_remove_node(flow_list, node) == -1) {
                    fprintf(stderr, "[ERROR] flow to remove not found\n");
                    exit(EXIT_FAILURE);
                }
                node = flow_list->head;
            } else {
            	break;
            }
        }
    }
}

#undef FLOW_MANAGEMENT_C
