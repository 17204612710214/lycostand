/**
 * @file running_stats.h
 *
 * @brief header file for running statistics calculations for flow feat
 *
 * @author Anonymous
 * @date Mar 30, 2021
*/

#ifndef RUNNING_STATS_H
#define RUNNING_STATS_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Public API */
/* Structures containing running statistics variables */
typedef struct runstats_data_s {
    uint64_t    sum;
    double      min;
    double      max;
    double      mean; 		/* current mean */
    double      Sn;   		/* current Sn corresponds to sum of (xk-mean)² */
    double      prev_mean;
    uint32_t    n_elements; /* number of elements added to statistics */
} runstats_data_t;

runstats_data_t runstats_init(double first_element);
void runstats_rst(runstats_data_t *runstats_data);
void runstats_update(runstats_data_t *stats, double new_element);
double runstats_get_min(runstats_data_t *stats);
double runstats_get_min_fwd_plus_bwd(runstats_data_t *fwdStats,
                                     runstats_data_t *bwdStats);
double runstats_get_max(runstats_data_t *stats);
double runstats_get_max_fwd_plus_bwd(runstats_data_t *fwdStats,
                                     runstats_data_t *bwdStats);
double runstats_get_mean(runstats_data_t *stats);
double runstats_get_mean_fwd_plus_bwd(runstats_data_t *fwdStats,
                                      runstats_data_t *bwdStats);
double runstats_get_std(runstats_data_t *stats);
double runstats_get_std_fwd_plus_bwd(runstats_data_t *fwdStats,
                                     runstats_data_t *bwdStats);
double runstats_get_var(runstats_data_t *stats);
uint64_t runstats_get_sum(runstats_data_t *stats);
uint64_t runstats_get_sum_fwd_plus_bwd(runstats_data_t *fwdStats,
                                       runstats_data_t *bwdStats);
double runstats_get_variance_fwd_plus_bwd(runstats_data_t *fwdStats,
                                          runstats_data_t *bwdStats);
void runstats_print(runstats_data_t *stats);
void runstats_print_fwd_plus_bwd(runstats_data_t *fwdStats,
                                 runstats_data_t *bwdStats);
void runstats_fileprint(runstats_data_t *stats, FILE *fp);
void runstats_fileprint_fwd_plus_bwd(runstats_data_t *fwdStats,
                                     runstats_data_t *bwdStats, FILE *fp);

/* Private API */
#ifdef RUNNING_STATS_C
double runstats_update_mean(double prev_mean, double new_element,
                            int32_t n_elements);
double runstats_update_Sn(double prev_mean, double new_mean, double new_element,
                          double prev_Sn);
#endif /* RUNNING_STATS_C */

#endif /* RUNNING_STATS_H */
