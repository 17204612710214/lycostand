/**
 * @file main.c
 *
 * @brief main program
 *
 * @author Anonymous
 * @date Mar 30, 2021
*/

#define MAIN_C

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <semaphore.h>
#include <sys/types.h>
#include <getopt.h>
#include <dirent.h>
#include <time.h>
#include <errno.h>
#include <signal.h>
#include "packet.h"
#include "running_stats.h"
#include "singly_linkedlist.h"
#include "feat_calc.h"
#include "flow_mngt.h"

/* Global variables */
sll_list_t *flow_list_ongoing;
sll_list_t *flow_list_terminated;
sll_list_t *flow_list_TCP_terminated;
latest_flow_t latest_flow;
char *lycos_file;
char *exectime_file;
inter_end_flows_t interEndFlows;
pthread_mutex_t mutex;
sem_t semaphore;
uint32_t thread1_finished = 0;
runstats_data_t statsExecTimes;
uint32_t flow_counter = 0;
flow_stats_t flow_stats;
pkt_stats_t pkt_stats;
char *pcap_path=NULL;
char *pcap_lycos_path=NULL;

/* prototypes */
void int_handler(int32_t sig);
int32_t extract_features(char *filename);
int32_t export_flows(void);
int32_t process_pcap(char* filename);

/* functions */
/**
 * @brief Display flow lists information if an interrupt signal occurred
 * @param[in] sig interrupt signal, CTRL-C
 */
void int_handler(int32_t sig)
{
    signal(sig, SIG_IGN);
    pkt_printstats();
    flow_printstats();
    printf("\nflow_counter = %d\n", flow_counter);
    printf("flow_list_ongoing.length = %d\n", flow_list_ongoing->length);
    printf("flow_list_ongoing.max_length = %d\n", flow_list_ongoing->max_length);
    printf("flow_list_terminated.length = %d\n", flow_list_terminated->length);
    printf("flow_list_terminated.max_length = %d\n", flow_list_terminated->max_length);
    printf("Program terminated by Ctrl-C\n");
    exit(EXIT_SUCCESS);
}

/**
 * @brief First thread function to extract flow based features from a PCAP file
 * @param[in] filename pointer to PCAP file
 * @return 0 when all PCAP file is processed
 */
int32_t extract_features(char *filename)
{
    pcap_t 	*handle;
	char 	errbuf[PCAP_ERRBUF_SIZE] = {0};
    char 	*logs_path = "./logs/";
    char 	*dev;
    char 	*lycos_ext = "_lycos.csv";
    char 	*exectime_ext = "_exectime.txt";
    int32_t path_len = strlen(pcap_path);
    int32_t name_len = strlen(filename);

    dev = calloc((path_len + name_len + 1), sizeof(char));
    strncpy(dev, pcap_path, path_len),
    strncat(dev, filename, name_len);
    path_len = strlen(pcap_lycos_path);
    strncpy(lycos_file, pcap_lycos_path, path_len);
    strncat(lycos_file, filename, name_len);
    strncat(lycos_file, lycos_ext, strlen(lycos_ext));
    path_len = strlen(logs_path);
    char *delim_ptr = strchr(filename, '-');
    name_len = delim_ptr - filename;
    strncpy(exectime_file, logs_path, path_len);
    strncat(exectime_file, filename, name_len);
    strncat(exectime_file, exectime_ext, strlen(exectime_ext));

    /* Write CSV header */
    print_write_file_header_row(lycos_file);

    /* 
     * open and close files to create empty files, potentially replacing
     * existing ones
     */
    FILE *fp;
    fp = fopen(exectime_file, "w");
    fclose(fp);

	handle = pcap_open_offline(dev, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "[ERROR] Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
	}

	/*
	 * pcap_loop will process each packet from the file
	 * number of packet to receive = -1 means endless reception
	 * pkt_process is a callback function to analyze each packet
	 */
    int nb_pckts_to_get = -1;
    pcap_loop(handle, nb_pckts_to_get, pkt_process, NULL);
    free(dev);
    printf("pcap_loop done\n");

    /* special treatment of flows that are not terminated yet */
    sll_apply_fn_to_list(flow_list_ongoing,
                         (int (*)(void *, void *)) flow_final_update,
                         &latest_flow);
	return 0;
}

/**
 * @brief Second thread function to write terminated flows in CSV file
 * @return 0 when all flows in flow_list_terminated are written in CSV file
 */
int32_t export_flows(void)
{
    flow_data_t *data;
    struct timespec ts;
    int32_t retval;
    while (1) {
        /* wait for terminated flow or a timeout of 1 second */
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 1;
        retval = sem_timedwait(&semaphore, &ts);
        if (retval == 0) {
            /* a flow is available */
            if (flow_list_terminated->length > 0) {
                /* write terminated flow as long as there is one available */
                pthread_mutex_lock(&mutex);
                data = (flow_data_t *) sll_get_head(flow_list_terminated)->data;
                flow_write(data, lycos_file);
                sll_remove_node(flow_list_terminated, flow_list_terminated->head);
                pthread_mutex_unlock(&mutex);
            }
        } else {
            if (errno != ETIMEDOUT) {
                fprintf(stderr, "[ERROR] export_flows errno: %d\n", errno);
            }
            /* timeout expired */
            if (thread1_finished == 1) {
                if (((uint32_t) semaphore.__align) != 0) {
                    fprintf(stderr,
                            "[WARNING] thread1 finished but flows still pending\n");
                }
                break;
            }
        }
    }
    return 0;
}

/**
 * @brief Main function to create two threads, one to handle feature extracting
 * and the other to handle CSV writing
 * @param[in] filename pointer to PCAP file
 * @return 0 when the two threads ended
 */
int32_t process_pcap(char* filename)
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
    printf("%s.%d - Processing %s\n", buffer, (int)(tv.tv_usec / 1000), filename);
    lycos_file = calloc(255, sizeof(char));
    exectime_file = calloc(255, sizeof(char));

    /* initialize flow structures */
    flow_list_ongoing = sll_init();
    flow_list_terminated = sll_init();
    flow_list_TCP_terminated = sll_init();
    flow_init(&latest_flow);
    memset(&flow_stats, 0, sizeof(flow_stats_t));
    memset(&pkt_stats, 0, sizeof(pkt_stats_t));

    /* initialize mutex and semaphore
     * mutex is used to protect access to the list of terminated flows
     * semaphore is used to indicate that data have been put into this list
     */
    pthread_mutex_init(&mutex, NULL);
    sem_init(&semaphore, 0, 0);
    if(errno != 0) {
        fprintf(stderr, "[ERROR] Couldn't initialize semaphore - errno %d\n", errno);
        exit(EXIT_FAILURE);
    }

    thread1_finished = 0;
    interEndFlows.last_flow_ts = 0;
    interEndFlows.terminated_flow_cnt = 0;
    statsExecTimes.n_elements = 0;

    /* Multi-threading process */
    pthread_t thread1;
    pthread_t thread2;
    pthread_attr_t attr;
    if (pthread_attr_init(&attr) != 0) {
        fprintf(stderr, "[ERROR] Couldn't initialize pthread\n");
        exit(EXIT_FAILURE);
    }
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
    pthread_create(&thread1, &attr, (void *(*)(void *)) extract_features, filename);
    pthread_create(&thread2, &attr, (void* (*)(void*)) export_flows, 0);
    int32_t retval = pthread_join(thread1, 0);
    /* inform thread2 that thread1 terminated */
    if (retval == 0) {
        gettimeofday(&tv, NULL);
        timestamp = tv.tv_sec;
        time_info = localtime( & timestamp );
        strftime (buffer, sizeof(buffer), "%T", time_info);
        printf("-------------------------------------------------------\n");
        printf("%s.%d - lycostand thread1 done ...\n", buffer, (int)(tv.tv_usec / 1000));

        thread1_finished = 1;
    }
    pthread_join(thread2, 0);
    pthread_attr_destroy(&attr);

    pkt_printstats();
    flow_printstats();
    printf("stats on execution times : \n");
    runstats_print(&statsExecTimes);

	/*
	 * note: initialization of a semaphore or mutex already initialized
	 * = undefined behavior
	 */
    pthread_mutex_destroy(&mutex);
    sem_destroy(&semaphore);
    sll_free(flow_list_ongoing);
    sll_free(flow_list_terminated);
    sll_free(flow_list_TCP_terminated);
    return 0;
}

/**
 * @brief Main process
 * @param[in] argc number of arguments
 * @param[in] argv pointer list to arguments
 * @return 0 when process terminated
 */
int main(int argc, char *argv[])
{
    int opt;
    struct timeval tv;
    time_t timestamp;
    struct tm *time_info;
    char buffer[64];

#ifndef ARG_BYPASS
    /* allow to process all PCAP files in an input directory
     * parse program arguments
     */
    if (argc != 5) {
        fprintf(stderr, "use ./lycostand -i path_to_pcap -o path_to_generated_files\n");
        exit(EXIT_FAILURE);
    }
    while ((opt = getopt(argc, argv, "hi:o:t:")) != -1)
    {
        switch(opt)
        {
            case 'h':
                printf("use ./lycostand -i path_to_pcap -o path_to_generated_files\n");
                break;
            case 'i':
                pcap_path = malloc(strlen(optarg)*sizeof(char));
                strcpy(pcap_path, optarg);
                break;
            case 'o':
                pcap_lycos_path = malloc(strlen(optarg)*sizeof(char));
                strcpy(pcap_lycos_path, optarg);
                break;
            case '?':
                fprintf(stderr, "Unknown option: %c\n", optopt);
                fprintf(stderr, "use ./lycostand -i path_to_pcap -o path_to_generated_files\n");
                exit(EXIT_FAILURE);
            case ':':
                fprintf(stderr, "Missing arg for %c\n", optopt);
                fprintf(stderr, "use ./lycostand -i path_to_pcap -o path_to_generated_files\n");
                exit(EXIT_FAILURE);
            default:
                fprintf(stderr, "use ./lycostand -i path_to_pcap -o path_to_generated_files\n");
                exit(EXIT_FAILURE);
        }
    }
    if ((pcap_path == NULL) || (pcap_lycos_path == NULL)) {
        fprintf(stderr, "use ./lycostand -i path_to_pcap -o path_to_generated_files\n");
        exit(EXIT_FAILURE);
    }
#endif /* !ARG_BYPASS */

    gettimeofday(&tv, NULL);
    timestamp = tv.tv_sec;
    time_info = localtime( & timestamp );
    strftime (buffer, sizeof(buffer), "%T", time_info);
    printf("-------------------------------------------------------\n");
    printf("%s.%d - lycostand starting ...\n", buffer, (int)(tv.tv_usec / 1000));

    /* install int handler to catch Ctrl-C */
    signal(SIGINT, int_handler);

#ifdef ARG_BYPASS
    /* Select manually the PCAP to process, one at a time */
    char *input_path = "./pcap/";
//    char *filename = "Monday-WorkingHours.pcap";
//    char *filename = "Tuesday-WorkingHours.pcap";
//    char *filename = "Wednesday-WorkingHours.pcap";
//    char *filename = "Thursday-WorkingHours.pcap";
//    char *filename = "Friday-WorkingHours.pcap";
	char *lycos_path = "./pcap_lycos/";
    pcap_path = calloc(256, sizeof(char));
    strncpy(pcap_path, input_path, strlen(input_path));
    pcap_lycos_path = calloc(256, sizeof(char));
    strncpy(pcap_lycos_path, lycos_path, strlen(lycos_path));
    process_pcap(filename);
#else
    /* Process each pcap file from input directory */
    DIR* pcap_dir = NULL;
    struct dirent* file;
    char *ext;
    pcap_dir = opendir(pcap_path);
    if (errno == EACCES) {
        fprintf(stderr, "cannot open pcap directory - errno=%d\n", EACCES);
    }
    while((file = readdir(pcap_dir)) != NULL)
    {
        ext = strrchr(file->d_name, '.');
        if ((ext != NULL) && !strcmp(ext, ".pcap"))
            process_pcap(file->d_name);
    }
#endif /* ARG_BYPASS */

    gettimeofday(&tv, NULL);
    timestamp = tv.tv_sec;
    time_info = localtime(&timestamp);
    strftime (buffer, sizeof(buffer), "%T", time_info);
    printf("-------------------------------------------------------\n");
    printf("%s.%d - lycostand done\n", buffer, (int)(tv.tv_usec / 1000));
    return(0);
}

#undef MAIN_C
