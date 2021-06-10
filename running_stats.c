/**
 * @file running_stats.c
 *
 * @brief implementation of running statistics calculations for flow feat,
 * based on Welford method
 *
 * @author Anonymous
 * @date Mar 30, 2021
*/

#define RUNNING_STATS_C

#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <errno.h>
#include "running_stats.h"

/**
 * @brief Initialize a statistics data structure with a first element
 * @param[in] first_element first element of the data structure
 * @return initialized statistics data structure
 */
runstats_data_t runstats_init(double first_element)
{
	runstats_data_t new_data;
    new_data.mean = first_element;
    new_data.Sn = 0.0;
    new_data.sum = (uint64_t) first_element;
    new_data.min = first_element;
    new_data.max = first_element;
    new_data.n_elements = 1;
	return new_data;
}

/**
 * @brief Reset a statistics data structure
 * @param[in] runstats_data running statistics structure
 * @return set all elements of running statistics data structure to 0
 */
void runstats_rst(runstats_data_t *runstats_data)
{
	memset(runstats_data, 0, sizeof(runstats_data_t));
}

/**
 * @brief Compute the running mean from previous computed mean, given a new
 * element
 * @param[in] prev_mean previous mean value
 * @param[in] new_element new element to add to statistics
 * @param[in] n_elements number of element already included in statistics
 * @return updated mean
 * @note Private function
 */
double runstats_update_mean(double prev_mean, double new_element,
                            int n_elements)
{
    double updated_mean;
    updated_mean = prev_mean + (new_element - prev_mean) / (n_elements);
    return updated_mean;
}

/**
 * @brief Compute the running sum for standard deviation and variance calculation
 * @param[in] prev_mean previous mean value
 * @param[in] new_mean new mean value
 * @param[in] new_element new element to add
 * @param[in] prev_Sn previous sum value
 * @return updated sum
 * @note Private function
 */
double runstats_update_Sn(double prev_mean, double new_mean,
                          double new_element, double prev_Sn)
{
    double new_Sn;
    new_Sn = prev_Sn + (new_element - prev_mean) * (new_element - new_mean);
    return new_Sn;
}

/**
 * @brief Perform an update of all the statistics (min, max, mean and Sn) of
 * a given runstats_data_t structure with a new element
 * @param[in,out] stats pointer to current statistics data
 * @param[in] new_element new element to add in statistics
 */
void runstats_update(runstats_data_t *stats, double new_element)
{
	if (stats != NULL) {
        stats->n_elements++;
        stats->prev_mean = stats->mean;
        stats->mean = runstats_update_mean(stats->prev_mean, new_element,
                                           stats->n_elements);
        stats->Sn = runstats_update_Sn(stats->prev_mean, stats->mean,
                                       new_element, stats->Sn);
		if (new_element < stats->min) {
            stats->min = new_element;
		} else if (new_element > stats->max) {
            stats->max = new_element;
		}
        stats->sum += (uint64_t)new_element;
	} else {
        fprintf(stderr, "[ERROR] Couldn't update stats: %d\n", EINVAL);
        exit(EXIT_FAILURE);
	}
}

/**
 * @brief Return minimum value from statistics data structure
 * @param[in] stats pointer to statistics data structure
 * @return minimum value
 */
double runstats_get_min(runstats_data_t *stats)
{
    return stats->min;
}

/**
 * @brief Return minimum value from forward and backward statistics
 * data structure
 * @param[in] fwdStats forward statistics data structure
 * @param[in] bwdStats backward statistics data structure
 * @return minimum value
 */
double runstats_get_min_fwd_plus_bwd(runstats_data_t *fwdStats,
                                     runstats_data_t *bwdStats)
{
	if ((bwdStats->n_elements != 0) && (fwdStats->n_elements != 0)) {
	    /* There are elements in both direction */
        if (fwdStats->min < bwdStats->min) {
            return fwdStats->min;
        }else{
            return bwdStats->min;
        }
	} else if (fwdStats->n_elements != 0) {
	    /* There is at least one element in forward direction
	     * but none in backward
	     */
        return runstats_get_min(fwdStats);
    } else {
    	/* There is not any element in forward direction, so there must
    	 * be at least one element in backward direction
    	 */
        return runstats_get_min(bwdStats);
    }
}

/**
 * @brief Return maximum value from statistics data structure
 * @param[in] stats poiter to statistics data structure
 * @return maximum value
 */
double runstats_get_max(runstats_data_t *stats)
{
    return stats->max;
}

/**
 * @brief Return maximum from forward and backward statistics data structure
 * @param[in] fwdStats pointer to forward statistics data structure
 * @param[in] bwdStats pointer to backward statistics data structure
 * @note The statistics computed separately for forward and backward can be
 * used to compute statistics on both directions.
 * @return maximum value
 */
double runstats_get_max_fwd_plus_bwd(runstats_data_t *fwdStats,
                                     runstats_data_t *bwdStats)
{
    if ((bwdStats->n_elements != 0) && (fwdStats->n_elements != 0)) {
    	/* There are elements in both direction */
        if (fwdStats->min < bwdStats->min) {
            return fwdStats->max;
        } else {
            return bwdStats->max;
        }
    } else if (fwdStats->n_elements != 0) {
    	/* There is at least one element in forward direction
    	 * but none in backward
    	 */
        return runstats_get_max(fwdStats);
    } else {
    	/* There is not any element in forward direction, so there must
    	 * be at least one element in backward direction
    	 */
        return runstats_get_max(bwdStats);
    }
}

/**
 * @brief Return mean value from statistics data structure
 * @param[in] stats pointer to statistics data structure
 * @return mean value
 */
double runstats_get_mean(runstats_data_t *stats)
{
	return stats->mean;
}

/**
 * @brief Return mean value from forward and backward statistics data structure
 * @param[in] fwdStats pointer to forward statistics data structure
 * @param[in] bwdStats pointer to backward statistics data structure
 * @note The statistics computed separately for forward and backward can be
 * used to compute statistics on both directions.
 * @return mean value
 */
double runstats_get_mean_fwd_plus_bwd(runstats_data_t *fwdStats,
                                      runstats_data_t *bwdStats)
{
    if  ((bwdStats->n_elements != 0) && (fwdStats->n_elements != 0)) {
    	/* There are elements in both direction */
        return (fwdStats->mean + bwdStats->mean) / 2;
    } else if (fwdStats->n_elements != 0) {
    	/* There is at least one element in forward direction
    	 * but none in backward
    	 */
        return runstats_get_mean(fwdStats);
    } else {
    	/* There is not any element in forward direction, so there must
    	 * be at least one element in backward direction
    	 */
        return runstats_get_mean(bwdStats);
    }
}

/**
 * @brief return standard deviation from statistics data structure
 * @param[in] stats pointer to statistics data structure
 * @return sample standard deviation value or 0 if statistics are calculated
 * with less than 2 elements
 * @note running standard deviation requires at least 2 elements
 */
double runstats_get_std(runstats_data_t *stats)
{
	if(stats->n_elements < 2){
		/* fprintf(stderr, "[WARNING] Couldn't get Sn: %d\n", EDOM); */
		return 0;
	}
	return sqrt((stats->Sn) / (stats->n_elements - 1));
}

/**
 * @brief Return standard deviation value from forward and backward statistics
 * data structure
 * @param[in] fwdStats pointer to forward statistics data structure
 * @param[in] bwdStats pointer to backward statistics data structure
 * @note The statistics computed separately for forward and backward can be
 * used to compute statistics on both directions.
 * @return standard deviation value
 */
double runstats_get_std_fwd_plus_bwd(runstats_data_t *fwdStats,
                                     runstats_data_t *bwdStats)
{
    if ((bwdStats->n_elements != 0) && (fwdStats->n_elements != 0)) {
    	/* There are elements in both direction */
        return sqrt((runstats_get_std(fwdStats) +
                     runstats_get_std(bwdStats)) / 2);
    } else if (fwdStats->n_elements != 0) {
    	/* There is at least one element in forward direction
    	 * but none in backward
    	 */
        return runstats_get_std(fwdStats);
    } else {
    	/* There is not any element in forward direction, so there must
    	 * be at least one element in backward direction
    	 */
    	return runstats_get_std(bwdStats);
    }
}

/**
 * @brief Return variance from statistics data structure
 * @param[in] stats pointer to statistics data structure
 * @return variance value or 0 if statistics are calculated with less than
 * 2 elements
 * @note Running variance requires at least 2 elements
 */
double runstats_get_var(runstats_data_t *stats)
{
	if (stats->n_elements < 2) {
		/* fprintf(stderr, "[WWARNING] Couldn't get Sn: %d\n", EDOM); */
		return 0;
	}
	return (stats->Sn) / (stats->n_elements - 1);
}

/**
 * @brief Return variance from forward and backward statistics data structure
 * @param[in] fwdStats pointer to forward statistics data structure
 * @param[in] bwdStats pointer to backward statistics data structure
 * @note The statistics computed separately for forward and backward can
 * be used to compute statistics on both directions.
 * @return variance value
 */
double runstats_get_variance_fwd_plus_bwd(runstats_data_t *fwdStats,
                                          runstats_data_t *bwdStats)
{
    if ((bwdStats->n_elements != 0) && (fwdStats->n_elements != 0)) {
    	/* There are elements in both direction */
        return (runstats_get_std(fwdStats) +
                runstats_get_std(bwdStats)) / 2 ;
    } else if (fwdStats->n_elements != 0) {
    	/* There is at least one element in forward direction
    	 * but none in backward
    	 */
       return runstats_get_var(fwdStats);
    } else {
    	/* There is not any element in forward direction, so there must
    	 * be at least one element in backward direction
    	 */
    	return runstats_get_var(bwdStats);
    }
}

/**
 * @brief Return sum of all elements added in statistics data structure
 * @param[in] stats pointer to statistics data structure
 * @return sum of all elements added in stats
 */
uint64_t runstats_get_sum(runstats_data_t *stats)
{
	return stats->sum;
}

/**
 * @brief Return sum of all elements from forward and backward statistics data
 * structure
 * @param[in] fwdStats pointer to forward statistics data structure
 * @param[in] bwdStats pointer to backward statistics data structure
 * @note The statistics computed separately for forward and backward can
 * be used to compute statistics on both directions.
 * @return sum of all forward and backward elements
 */
uint64_t runstats_get_sum_fwd_plus_bwd(runstats_data_t *fwdStats,
                                       runstats_data_t *bwdStats)
{
	if ((bwdStats->n_elements != 0) && (fwdStats->n_elements != 0)) {
    	/* There are elements in both direction */
		return fwdStats->sum + bwdStats->sum;
	} else if (fwdStats->n_elements != 0) {
	    /* There is at least one element in forward direction
	     * but none in backward
	     */
		return runstats_get_sum(fwdStats);
	} else {
    	/* There is not any element in forward direction, so there must
    	 * be at least one element in backward direction */
		return runstats_get_sum(bwdStats);
	}
}

/**
 * @brief Print elements of a given statistics data structure to stdout
 * @param[in] stats pointer to statistics data structure to print
 */
void runstats_print(runstats_data_t *stats)
{
    printf("\tn_elements: %d\n", stats->n_elements);
    printf("\tMean: %lf\n", stats->mean);
    printf("\tSn: %lf\n", stats->Sn);
    printf("\tVar pop: %lf\n", (stats->Sn) / (stats->n_elements));
    printf("\tVar samp: %lf\n", runstats_get_var(stats));
    printf("\tStd pop: %lf\n", sqrt((stats->Sn) / (stats->n_elements)));
    printf("\tStd samp: %lf\n", runstats_get_std(stats));
    printf("\tMin: %lf\n", stats->min);
    printf("\tMax: %lf\n", stats->max);
    printf("\tTotal: %lu\n", stats->sum);
}

/**
 * @brief Print statistics of a given statistics data structure to a file
 * @param[in] stats pointer to statistics data structure to print
 * @param[in] fp pointer to file handler
 */
void runstats_fileprint(runstats_data_t *stats, FILE *fp)
{
    fprintf(fp,"%lf,", stats->mean);
    fprintf(fp,"%lf,", sqrt((stats->Sn) / (stats->n_elements)));
    fprintf(fp,"%lf,", stats->min);
    fprintf(fp,"%lf,", stats->max);
    fprintf(fp,"%lu,", stats->sum);
}

/**
 * @brief Print statistics of given forward and backward statistics data
 * structure to stdout
 * @param[in] fwdStats pointer to forward statistics data structure
 * @param[in] bwdStats pointer to backward statistics data structure
 * @note The statistics computed separately for forward and backward can
 * be used to compute statistics on both directions.
 */
void runstats_print_fwd_plus_bwd(runstats_data_t *fwdStats,
                                 runstats_data_t *bwdStats)
{
    if (bwdStats->n_elements > 0) {
        printf("\tMean: %lf\n", (fwdStats->mean + bwdStats->mean) / 2);
        double var;
        var = ((fwdStats->Sn / fwdStats->n_elements) + \
               (bwdStats->Sn / bwdStats->n_elements)) / 2;
        printf("\tStd: %lf\n", sqrt(var));

        if (fwdStats->min < bwdStats->min) {
            printf("\tMin: %lf\n", fwdStats->min);
        } else {
            printf("\tMin: %lf\n", bwdStats->min);
        }

        if (fwdStats->max > bwdStats->max) {
            printf("\tMax: %lf\n", fwdStats->max);
        } else {
            printf("\tMax: %lf\n", bwdStats->max);
        }
        printf("\tTotal: %lu\n", fwdStats->sum + bwdStats->sum);
    } else {
        runstats_print(fwdStats);
    }
}

/**
 * @brief Print statistics of given forward and backward statistics data
 * structure to file
 * @param[in] fwdStats pointer to forward statistics data structure
 * @param[in] bwdStats pointer to backward statistics data structure
 * @param[in] fp pointer to file handler
 */
void runstats_fileprint_fwd_plus_bwd(runstats_data_t *fwdStats,
                                     runstats_data_t *bwdStats, FILE *fp)
{
    if (bwdStats->n_elements > 0) {
        fprintf(fp, "%lf,", (fwdStats->mean + bwdStats->mean) / 2);
        double var;
        var = ((fwdStats->Sn / fwdStats->n_elements) + \
               (bwdStats->Sn / bwdStats->n_elements)) / 2;
        fprintf(fp, "%lf,",sqrt(var));
	
		if (fwdStats->min < bwdStats->min) {
			fprintf(fp, "%lf,", fwdStats->min);
		} else {
			fprintf(fp, "%lf,", bwdStats->min);
		}

		if (fwdStats->max > bwdStats->max) {
			fprintf(fp, "%lf,", fwdStats->max);
		} else {
			fprintf(fp, "%lf,", bwdStats->max);
		}
		fprintf(fp, "%lu,", fwdStats->sum + bwdStats->sum);
	} else {
        runstats_fileprint(fwdStats, fp);
	}
}

#undef RUNNING_STATS_C
