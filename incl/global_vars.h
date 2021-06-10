/**
 * @file global_vars.h
 *
 * @brief header file for global variables initialized in main.c and used in
 * other files
 *
 * @author Anonymous
 * @date Mar 30, 2021
*/

#ifndef GLOBAL_VARS_H
#define GLOBAL_VARS_H

#include <stdio.h>
#include <semaphore.h>
#include "flow_mngt.h"
#include "running_stats.h"

/* All global variables are declared in main.c */
extern sll_list_t 	 	*flow_list_ongoing;
extern sll_list_t 		*flow_list_terminated;
/* Declaration of TCP_terminated flow list*/
extern sll_list_t 	 	*flow_list_TCP_terminated;
extern latest_flow_t 	latest_flow;
extern char 		 	*lycos_file;
extern pthread_mutex_t 	mutex;
extern sem_t semaphore;
extern flow_stats_t 	flow_stats;
extern pkt_stats_t 		pkt_stats;

#endif /*GLOBAL_VARS_H */
