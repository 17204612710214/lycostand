/**
 * @file feat_calc.h
 *
 * @brief header file for feat calculation
 *
 * @author Anonymous
 * @date Mar 30, 2021
*/

#ifndef FEATURES_CALCULATION_H
#define FEATURES_CALCULATION_H

#include "running_stats.h"
#include "packet.h"

/* Public API */
/* Structure containing flow features */
typedef struct features_s {
    double 			flow_duration_us;
    uint32_t 		total_fwd_pkt;
    uint32_t 		total_bwd_pkt;
    double 			fwd_pkt_per_s;
    double 			bwd_pkt_per_s;
    double 			pkt_per_s;
    double 			fwd_bytes_per_s;
    double 			bwd_bytes_per_s;
    double 			bytes_per_s;
    uint32_t 		fwd_hdr_len;
    uint32_t 		bwd_hdr_len;
    runstats_data_t fwd_len_pkt_stats;
    runstats_data_t bwd_len_pkt_stats;
    runstats_data_t len_pkt_stats;
    runstats_data_t fwd_iat_stats;
    runstats_data_t bwd_iat_stats;
    runstats_data_t iat_stats;
    uint32_t 		fwd_psh_flag_cnt;
    uint32_t 		bwd_psh_flag_cnt;
    uint32_t 		fwd_urg_flag_cnt;
    uint32_t 		bwd_urg_flag_cnt;
    uint32_t 		fin_flag_cnt;
    uint32_t 		syn_flag_cnt;
    uint32_t 		rst_flag_cnt;
    uint32_t 		psh_flag_cnt;
    uint32_t 		ack_flag_cnt;
    uint32_t 		urg_flag_cnt;
    uint32_t 		ece_flag_cnt;
    uint32_t 		cwr_flag_cnt;
    uint32_t 		fwd_non_empty_pkt_cnt;
    uint32_t 		bwd_non_empty_pkt_cnt;
    runstats_data_t active;
    runstats_data_t idle;
    double 			fwd_bytes_per_bulk_mean;
    double 			fwd_pkt_per_bulk_mean;
    double 			fwd_bulk_rate_mean;
    double 			bwd_bytes_per_bulk_mean;
    double 			bwd_pkt_per_bulk_mean;
    double 			bwd_bulk_rate_mean;
    double 			fwd_subflow_pkt;
    double 			fwd_subflow_bytes;
    double 			bwd_subflow_pkt;
    double 			bwd_subflow_bytes;
    double 			down_up_ratio;
    uint16_t 		fwd_init_win_bytes;
    uint16_t 		bwd_init_win_bytes;
    uint16_t 		fwd_hdr_len_min;
    uint16_t 		bwd_hdr_len_min;
} features_t;

/* Structure containing timestamps relative to a flow */
typedef struct feat_update_timestamps_s {
    double last_flow_ts;
    double last_flow_fwd_ts;
    double last_flow_bwd_ts;
    double begin_active;
} feat_update_timestamps_t;

/* Structure containing bulk relative features */
typedef struct bulk_s {
    double 	 fwd_duration;
    uint32_t fwd_pkt_cnt;
    uint32_t fwd_size_total;
    uint32_t fwd_state_cnt;
    uint32_t fwd_pkt_cnt_helper;
    double 	 fwd_start_helper;
    uint32_t fwd_size_helper;
    double 	 fwd_last_ts;
    double 	 bwd_duration;
    uint32_t bwd_pkt_cnt;
    uint32_t bwd_size_total;
    uint32_t bwd_state_cnt;
    uint32_t bwd_pkt_cnt_helper;
    double 	 bwd_start_helper;
    uint32_t bwd_size_helper;
    double 	 bwd_last_ts;
} bulk_t;

/* Structure containing flow data */
typedef struct flow_data_s {
    /* ID fields */
    uint32_t 	src_ipv4;
    uint32_t 	dst_ipv4;
    uint16_t 	src_port;
    uint16_t 	dst_port;
    uint16_t 	ip_version;
    uint8_t  	ip_prot;
    uint8_t  	padding;
    /* Time information */
    double 	 	first_ts;
    double 	 	last_ts;
    double   	last_fwd_ts;
    double   	last_bwd_ts;
    double   	beg_act_us;
    /* Features */
    features_t 	feat;
    bulk_t 		bulk;
    uint32_t 	subflow_cnt;
} flow_data_t;

/* Structure of flow_list_TCP_terminated data */
typedef struct flow_data_TCP_terminated_s {
    /* ID fields */
	uint32_t 	src_ipv4;
	uint32_t 	dst_ipv4;
    uint16_t 	src_port;
    uint16_t 	dst_port;
    uint8_t  	ip_prot;
    /* Time information */
    double 		last_ts;
} flow_data_TCP_terminated_t;

features_t  featcalc_init_feat_fwd(pkt_info_t *info);
features_t  featcalc_init_feat_bwd(pkt_info_t *info);
void        featcalc_init_bulk(bulk_t *bulk);
void        featcalc_update(features_t *feat, pkt_info_t *info,
                            feat_update_timestamps_t ts);
double      featcalc_update_duration(pkt_info_t *info, double first_ts);
void        featcalc_update_active_idle(features_t *feat, pkt_info_t *info ,
                                        feat_update_timestamps_t ts,
                                        double *beg_act_us,
                                        double act_timeout_us);
void        featcalc_endOfFlow_update(features_t *feat, bulk_t bulk,
                                      uint32_t subflow_cnt);
void 		featcalc_update_bulk(pkt_info_t *info, flow_data_t *data);
void 		featcalc_update_subflow_cnt(flow_data_t *data, double current_ts,
                                        double last_seen_ts);

/* Private API */
#ifdef FEATURES_CALCULATION_C
void 		featcalc_update_bwd_bulk(pkt_info_t *info, flow_data_t *data);
void 		featcalc_update_fwd_bulk(pkt_info_t *info, flow_data_t *data);
#endif /* FEATURES_CALCULATION_C */

#endif /* FEATURES_CALCULATION_H */
