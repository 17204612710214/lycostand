/**
 * @file feat_calc.c
 * @brief Calculate feat and update statistics
 *
 * @author Anonymous
 * @date Mar 30, 2021
*/

#define FEATURES_CALCULATION_C

#include <stdlib.h>
#include <netinet/in.h>
#include <string.h>
#include "feat_calc.h"
#include "flow_mngt.h"

/**
 * @brief Initialization function in forward direction
 * @param[in] info pointer to structure containing packet information
 * @return structure containing the features
 * @note Some statistics (active, idle, statistics on backward packets...) must
 * be initialized later, because they need more packets to compute their first
 * statistics.
 */
features_t featcalc_init_feat_fwd(pkt_info_t *info)
{
	features_t feat;
	/* Initialize all features to 0 */
	memset(&feat, 0, sizeof(features_t));
    feat.total_fwd_pkt = 1;
    feat.fwd_hdr_len = info->hdr_len;
    feat.fwd_len_pkt_stats = runstats_init((double)(info->pkt_len));
    feat.len_pkt_stats = runstats_init((double)(info->pkt_len));
	/* Flags initialization */
	if (info->ip_prot == PROT_TCP) {
		if (((info->tcp->flags) & TCP_FIN) != 0){
			feat.fin_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_SYN) != 0) {
			feat.syn_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_PSH) != 0) {
			feat.psh_flag_cnt = 1;
			feat.fwd_psh_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_URG) != 0) {
			feat.urg_flag_cnt = 1;
			feat.fwd_urg_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_RST) != 0) {
            feat.rst_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_ACK) != 0) {
            feat.ack_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_ECE) != 0) {
            feat.ece_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_CWR) != 0) {
            feat.cwr_flag_cnt = 1;
		}
		feat.fwd_init_win_bytes = ntohs(info->tcp->window);
	}
    if(info->pkt_len > 0){
        feat.fwd_non_empty_pkt_cnt = 1;
    }
    feat.fwd_hdr_len_min = info -> hdr_len;
	return feat;
}

/**
 * @brief Initialization function in backward direction
 * @param[in] info pointer to structure containing packet information
 * @return structure containing the features
 * @note Some statistics (active, idle, statistics on forward packets) must be
 * initialized later, because they need more packets to compute their first
 * statistics.
 */
features_t featcalc_init_feat_bwd(pkt_info_t *info)
{
	features_t feat;
	/* Initialize all features to 0 */
	memset(&feat, 0, sizeof(features_t));
    feat.total_bwd_pkt = 1;
    feat.bwd_hdr_len = info->hdr_len;
    feat.bwd_len_pkt_stats = runstats_init((double)(info->pkt_len));
    feat.len_pkt_stats = runstats_init((double)(info->pkt_len));
	/* Flags initialization */
	if (info->ip_prot == PROT_TCP) {
		if (((info->tcp->flags) & TCP_FIN) != 0){
			feat.fin_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_SYN) != 0) {
			feat.syn_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_PSH) != 0) {
			feat.psh_flag_cnt = 1;
			feat.bwd_psh_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_URG) != 0) {
			feat.urg_flag_cnt = 1;
			feat.bwd_urg_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_RST) != 0) {
            feat.rst_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_ACK) != 0) {
            feat.ack_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_ECE) != 0) {
            feat.ece_flag_cnt = 1;
		}
		if (((info->tcp->flags) & TCP_CWR) != 0) {
            feat.cwr_flag_cnt = 1;
		}
        feat.bwd_init_win_bytes = ntohs(info->tcp->window);
	}
    if(info->pkt_len > 0){
        feat.bwd_non_empty_pkt_cnt = 1;
    }
    feat.bwd_hdr_len_min = info -> hdr_len;
	return feat;
}

/**
 * @brief initialize all bulk variables to 0
 * @param bulk pointer to bulk structure containing all calculation variables
 * to update bulk
 */
void featcalc_init_bulk(bulk_t *bulk) {
    memset(bulk, 0, sizeof(bulk_t));
}

/**
 * @brief update features using information from an additional packet
 * @param[in,out] feat pointer to structure containing the features
 * @param[in] info pointer to structure containing information related to a
 * new packet
 * @param[in] ts structure containing timestamps
 */
void featcalc_update(features_t *feat, pkt_info_t *info ,
                     feat_update_timestamps_t ts)
{
    double ts_diff;
	runstats_update(&feat->len_pkt_stats, (double)(info->pkt_len));
	if (info->direction == FLOW_DIR_FWD) {
        /* update features on forward direction: */
		if (feat->total_fwd_pkt == 0) {
			feat->fwd_hdr_len_min = info->hdr_len;
		} else {
			if (info->hdr_len < feat->fwd_hdr_len_min) {
				feat->fwd_hdr_len_min = info->hdr_len;
			}
		}
        feat->total_fwd_pkt += 1;
        feat->fwd_hdr_len += info->hdr_len;
		runstats_update(&feat->fwd_len_pkt_stats, (double)(info->pkt_len));
		ts_diff = *info->ts - ts.last_flow_fwd_ts;
		if (feat->total_fwd_pkt > 1) {
			if(feat->total_fwd_pkt == 2) {
				feat->fwd_iat_stats = runstats_init(ts_diff);
			} else {
				runstats_update(&feat->fwd_iat_stats, ts_diff);
			}
		}
		if (info->ip_prot == PROT_TCP) {
			if(((info->tcp->flags) & TCP_PSH ) != 0){
				feat->fwd_psh_flag_cnt += 1;
			}
			if(((info->tcp->flags) & TCP_URG ) != 0){
				feat->fwd_urg_flag_cnt += 1;
			}
			if(feat->total_fwd_pkt == 1) {
				feat->fwd_init_win_bytes = ntohs(info->tcp->window);
			}
		}
		if(info->pkt_len > 0) {
            feat->fwd_non_empty_pkt_cnt += 1;
		}
	} else if (info->direction == FLOW_DIR_BWD) {
		/* update feat on backward direction: */
		if (feat->total_bwd_pkt == 0) {
			feat->bwd_hdr_len_min = info->hdr_len;
		} else {
			if (info->hdr_len < feat->bwd_hdr_len_min) {
				feat->bwd_hdr_len_min = info->hdr_len;
			}
		}
        feat->total_bwd_pkt += 1;
        feat->bwd_hdr_len += info->hdr_len;
        runstats_update(&feat->bwd_len_pkt_stats, (double)(info->pkt_len));
		ts_diff = *info->ts - ts.last_flow_bwd_ts;
		if (feat->total_bwd_pkt > 1) {
			if (feat->total_bwd_pkt == 2) {
				feat->bwd_iat_stats = runstats_init(ts_diff);
			} else {
				runstats_update(&feat->bwd_iat_stats, ts_diff);
			}
		}
		if (info->ip_prot == PROT_TCP) {
			if (((info->tcp->flags) & TCP_PSH ) != 0) {
				feat->bwd_psh_flag_cnt += 1;
			}
			if (((info->tcp->flags) & TCP_URG ) != 0) {
				feat->bwd_urg_flag_cnt += 1;
			}
			if(feat->total_bwd_pkt == 1) {
				feat->bwd_init_win_bytes = ntohs(info->tcp->window);
			}
		}
		if(info->pkt_len > 0) {
			feat->bwd_non_empty_pkt_cnt += 1;
		}
	}
	/*Update flags:*/
	if (info->ip_prot == PROT_TCP) {
		if (((info->tcp->flags) & TCP_FIN) != 0) {
			feat->fin_flag_cnt += 1;
		}
		if (((info->tcp->flags) & TCP_URG) != 0) {
			feat->urg_flag_cnt += 1;
		}
		if (((info->tcp->flags) & TCP_SYN) != 0) {
			feat->syn_flag_cnt += 1;
		}
		if (((info->tcp->flags) & TCP_PSH) != 0) {
			feat->psh_flag_cnt += 1;
		}
		if (((info->tcp->flags) & TCP_RST) != 0) {
			feat->rst_flag_cnt += 1;
		}
		if (((info->tcp->flags) & TCP_ACK) != 0) {
			feat->ack_flag_cnt += 1;
		}
		if (((info->tcp->flags) & TCP_ECE) != 0) {
			feat->ece_flag_cnt += 1;
		}
		if (((info->tcp->flags) & TCP_CWR) != 0) {
			feat->cwr_flag_cnt += 1;
		}
	}
	/* Update IAT statistics: */
    ts_diff = *info->ts - ts.last_flow_ts;
	if ((feat->total_fwd_pkt + feat->total_bwd_pkt) == 2) {
        feat->iat_stats = runstats_init(ts_diff);
	} else {
		runstats_update(&feat->iat_stats, ts_diff);
	}
}

/**
 * @brief Update flow duration
 * @param[in] info pointer to structure containing information related to a
 * new packet
 * @param[in] first_ts timestamp of the first packet in microseconds
 * @return duration in microseconds between timestamp of new packet and
 * timestamp of the first packet of the flow
 */
double featcalc_update_duration(pkt_info_t *info, double first_ts)
{
    double duration = *info->ts - first_ts;
    return duration;
}

/**
 * @brief Update active and idle features
 * @param[in,out] feat pointer to structure containing the features
 * @param[in] info pointer to structure containing information related to a
 * new packet
 * @param[in] ts structure containing timestamps
 * @param[in,out] beg_act_us pointer to timestamp in microseconds corresponding
 * to the beginning of activity
 * @param[in] act_timeout_us activity timeout in microseconds
 */
void featcalc_update_active_idle(features_t *feat, pkt_info_t *info ,
                                 feat_update_timestamps_t ts,
                                 double *beg_act_us, double act_timeout_us)
{
	if (feat->active.n_elements == 0) {
		if ((*info->ts - ts.last_flow_ts) > act_timeout_us) {
			if ((ts.last_flow_ts - *beg_act_us) > 0) {
                feat->active = runstats_init(ts.last_flow_ts - *beg_act_us);
			}
			if(feat->idle.n_elements == 0) {
                feat->idle = runstats_init(*info->ts - ts.last_flow_ts);
			} else {
				runstats_update(&feat->idle, *info->ts - ts.last_flow_ts);
			}
			*beg_act_us = *info->ts;
		}
	} else {
		if ((*info->ts - ts.last_flow_ts) > act_timeout_us) {
			if ((ts.last_flow_ts - *beg_act_us) > 0) {
				runstats_update(&feat->active, ts.last_flow_ts - *beg_act_us);
			}
			if(feat->idle.n_elements == 0) {
                feat->idle = runstats_init(*info->ts - ts.last_flow_ts);
			} else {
				runstats_update(&feat->idle, *info->ts - ts.last_flow_ts);
			}
			*beg_act_us = *info->ts;
		}
	}
}

/**
 * @brief Update features when a flow is terminated
 * @param[in,out] feat pointer to structure containing the features
 * @param[in] bulk structure containing bulk information
 * @param[in] subflow_cnt total number of subflow in current flow
 * @note It allows to properly update statistics at the end of the flow.
 */
void featcalc_endOfFlow_update(features_t *feat, bulk_t bulk,
                               uint32_t subflow_cnt)
{
	double duration_s = feat->flow_duration_us / 1000000;
	if (duration_s > 0) {
        feat->fwd_pkt_per_s = (double)(feat->total_fwd_pkt) / duration_s;
        feat->bwd_pkt_per_s = (double)(feat->total_bwd_pkt) / duration_s;
        feat->fwd_bytes_per_s = (double)(feat->fwd_len_pkt_stats.sum) / duration_s;
        feat->bwd_bytes_per_s = (double)(feat->bwd_len_pkt_stats.sum) / duration_s;
	}
    feat->pkt_per_s = feat->fwd_pkt_per_s + feat->bwd_pkt_per_s;
    feat->bytes_per_s = feat->fwd_bytes_per_s + feat->bwd_bytes_per_s;
	double bulk_fwd_duration_s = bulk.fwd_duration / 1000000;
	double bulk_bwd_duration_s = bulk.bwd_duration / 1000000;
	if (bulk.fwd_state_cnt > 0) {
        feat->fwd_bytes_per_bulk_mean = (double)(bulk.fwd_size_total) / (double)(bulk.fwd_state_cnt);
        feat->fwd_pkt_per_bulk_mean = (double)(bulk.fwd_pkt_cnt) / (double)(bulk.fwd_state_cnt);
	}
	if (bulk_fwd_duration_s > 0) {
        feat->fwd_bulk_rate_mean = (double)(bulk.fwd_size_total) / (double)(bulk_fwd_duration_s);
	}
	if (bulk.bwd_state_cnt > 0) {
        feat->bwd_bytes_per_bulk_mean = (double)(bulk.bwd_size_total) / (double)(bulk.bwd_state_cnt);
        feat->bwd_pkt_per_bulk_mean = (double)(bulk.bwd_pkt_cnt) / (double)(bulk.bwd_state_cnt);
	}
	if (bulk_bwd_duration_s > 0) {
        feat->bwd_bulk_rate_mean = (double)(bulk.bwd_size_total) / (double)(bulk_bwd_duration_s);
	}
	if(subflow_cnt != 0){
        feat->fwd_subflow_pkt = (double)(feat->total_fwd_pkt) / (double)(subflow_cnt);
        feat->fwd_subflow_bytes = (double)(feat->fwd_len_pkt_stats.sum) / (double)(subflow_cnt);
        feat->bwd_subflow_pkt = (double)(feat->total_bwd_pkt) / (double)(subflow_cnt);
        feat->bwd_subflow_bytes = (double)(feat->bwd_len_pkt_stats.sum) / (double)(subflow_cnt);
	}
	if (feat->total_fwd_pkt != 0) {
		feat->down_up_ratio = (double)(feat->total_bwd_pkt) / (double)(feat->total_fwd_pkt);
	}
}

/**
 * @brief Update bulk features in forward direction
 * @param[in] info pointer to structure containing information  related to a
 * new packet
 * @param[in,out] data pointer to structure containing data of the flow to update
 */
void featcalc_update_fwd_bulk(pkt_info_t *info, flow_data_t *data)
{
    double ts_diff;
    if (data->bulk.bwd_last_ts > data->bulk.fwd_start_helper) {
        data->bulk.fwd_start_helper = 0;
        //printf("bwd_last_ts, fwd_start_helper : %llu, %llu\n",data->bulk.bwd_last_ts, data->bulk.fwd_start_helper);
    }
    if (info->pkt_len < 1) {
        //printf("packet len<1\n");
        return;
    }
    if (data->bulk.fwd_start_helper == 0) {
        //printf("data->bulk.fwd_start_helper == 0\n");
        data->bulk.fwd_start_helper = *info->ts;
        data->bulk.fwd_pkt_cnt_helper = 1;
        data->bulk.fwd_size_helper = info->pkt_len;
        data->bulk.fwd_last_ts = *info->ts;
    } else {
        if ((*info->ts - data->bulk.fwd_last_ts) > 1000000) {
            //printf("(*info->ts - data->bulk.fwd_last_ts)>1000000\n");
            data->bulk.fwd_start_helper = *info->ts;
            data->bulk.fwd_last_ts = *info->ts;
            data->bulk.fwd_pkt_cnt_helper = 1;
            data->bulk.fwd_size_helper = info->pkt_len;
        } else {
            //printf("fwd_pkt_cnt_helper : %u\n", data->bulk.fwd_pkt_cnt_helper);
            data->bulk.fwd_pkt_cnt_helper += 1;
            data->bulk.fwd_size_helper += info->pkt_len;
            if (data->bulk.fwd_pkt_cnt_helper == 4) {
                //printf("data->bulk.fwd_pkt_cnt_helper == 4\n");
                data->bulk.fwd_state_cnt += 1;
                data->bulk.fwd_pkt_cnt += data->bulk.fwd_pkt_cnt_helper;
                data->bulk.fwd_size_total += data->bulk.fwd_size_helper;
                ts_diff = *info->ts - data->bulk.fwd_start_helper;
                if(ts_diff > 0) {
                    data->bulk.fwd_duration += ts_diff;
                }
            } else if (data->bulk.fwd_pkt_cnt_helper > 4) {
                //printf("fwd_pkt_cnt : %u\n",data->bulk.fwd_pkt_cnt);
                data->bulk.fwd_pkt_cnt += 1;
                data->bulk.fwd_size_total += info->pkt_len;
                ts_diff = *info->ts - data->bulk.fwd_last_ts;
                if (ts_diff > 0) {
                    data->bulk.fwd_duration += ts_diff;
                }
            }
            data->bulk.fwd_last_ts = *info->ts;
        }
    }
}

/**
 * @brief Update bulk features in backward direction
 * @param[in] info pointer to structure containing information related to a
 * new packet
 * @param[in,out] data pointer to structure containing data of the flow to update
 */
void featcalc_update_bwd_bulk(pkt_info_t *info, flow_data_t *data)
{
    double ts_diff;
    if (data->bulk.fwd_last_ts > data->bulk.bwd_start_helper) {
        data->bulk.bwd_start_helper = 0;
    }
    if(info->pkt_len < 1) {
        return;
    }
    if (data->bulk.bwd_start_helper == 0) {
        data->bulk.bwd_start_helper = *info->ts;
        data->bulk.bwd_pkt_cnt_helper = 1;
        data->bulk.bwd_size_helper = info->pkt_len;
        data->bulk.bwd_last_ts = *(info->ts);
    } else {
        if ((*info->ts - data->bulk.bwd_last_ts) > 1000000) {
            data->bulk.bwd_start_helper = *info->ts;
            data->bulk.bwd_last_ts = *info->ts;
            data->bulk.bwd_pkt_cnt_helper = 1;
            data->bulk.bwd_size_helper = info->pkt_len;
        } else {
            data->bulk.bwd_pkt_cnt_helper += 1;
            data->bulk.bwd_size_helper += info->pkt_len;
            if (data->bulk.bwd_pkt_cnt_helper == 4) {
                data->bulk.bwd_state_cnt += 1;
                data->bulk.bwd_pkt_cnt += data->bulk.bwd_pkt_cnt_helper;
                data->bulk.bwd_size_total += data->bulk.bwd_size_helper;
                ts_diff = *info->ts - data->bulk.bwd_start_helper;
                if(ts_diff > 0){
                    data->bulk.bwd_duration += ts_diff;
                }
            } else if (data->bulk.bwd_pkt_cnt_helper > 4) {
                data->bulk.bwd_pkt_cnt += 1;
                data->bulk.bwd_size_total += info->pkt_len;
                ts_diff = *info->ts - data->bulk.bwd_last_ts;
                if(ts_diff > 0) {
                    data->bulk.bwd_duration += ts_diff;
                }
            }
            data->bulk.bwd_last_ts = *info->ts;
        }
    }
}

/**
 * @brief Update bulk features
 * @param[in] info pointer to structure containing information related to a
 * new packet
 * @param[in,out] data pointer to structure containing data of the flow to update
 */
void featcalc_update_bulk(pkt_info_t *info, flow_data_t *data){
    if(info->direction == FLOW_DIR_FWD) {
        featcalc_update_fwd_bulk(info, data);
    } else {
        featcalc_update_bwd_bulk(info, data);
    }
}

/**
 * @brief Update subflow counter
 * @param[in,out] data pointer to structure containing data of the flow to update
 * @param[in] current_ts timestamp of the new packet
 * @param[in] last_seen_ts previous packet timestamp
 */
void featcalc_update_subflow_cnt(flow_data_t *data, double current_ts,
                                 double last_seen_ts)
{
    if ((current_ts - last_seen_ts) > 1000000) {
        data->subflow_cnt++;
    }
}

#undef FEATURES_CALCULATION_C
