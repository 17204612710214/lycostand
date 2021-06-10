/**
 * @file singly_linkedlist.h
 *
 * @brief header file for singly linked list implementation
 *
 * @author Anonymous
 * @date Mar 30, 2021
*/

#ifndef SINGLY_LINKED_LIST_H
#define SINGLY_LINKED_LIST_H

#include <stdint.h>

/* Public API */
/* Node structure */
typedef struct sll_node_s {
	void                *data;	/* pointer to current node data */
	struct sll_node_s   *next; 	/* pointer to next node in list */
} sll_node_t;

/* Singly linked list structure */
typedef struct sll_list_s {
    sll_node_t *head;			/* first element */
    sll_node_t *tail;			/* last element */
    uint32_t    length;
    uint32_t    max_length;
} sll_list_t;

sll_list_t *sll_init(void);
sll_node_t *sll_insert_head(sll_list_t *list, void *data);
sll_node_t *sll_insert_tail(sll_list_t *list, void *data);
int32_t 	sll_remove_node(sll_list_t *list, sll_node_t *node);
sll_node_t *sll_get_head(sll_list_t *list);
sll_node_t *sll_get_tail(sll_list_t *list);
sll_node_t *sll_find(sll_list_t *list, int32_t (*cmp_fn)(void*, void*),
                     void *data);
int32_t		sll_apply_fn_to_list(sll_list_t *list,
                                    int32_t (*apply_fn)(void*, void*),
                                    void* args);
int32_t		sll_free(sll_list_t *list);

/* Private API */
#ifdef SINGLY_LINKED_LIST_C
#endif /* SINGLY_LINKED_LIST_C */

#endif /* SINGLY_LINKED_LIST_H */

