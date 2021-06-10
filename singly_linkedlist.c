/**
 * @file singly_linkedlist.c
 *
 * @brief implementation of lingky linked list
 *
 * @author Anonymous
 * @date Mar 30, 2021
*/

#define SINGLY_LINKED_LIST_C

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "singly_linkedlist.h"

/**
 * @brief Initialize a singly linked list
 * @return pointer to a list
 */
sll_list_t *sll_init(void)
{
    sll_list_t *list;
    list = malloc(sizeof(sll_list_t));
    if (list != NULL) {
        list->head = (sll_node_t *) NULL;
        list->tail = (sll_node_t *) NULL;
        list->length = 0;
        list->max_length = 0;
    } else {
        fprintf(stderr, "[ERROR] sll_init errno: %d", ENOMEM);
    }
    return list;
}

/**
 * @brief Insert a new node at the head of the list
 * @param[in] list pointer to the list in which add a new node
 * @param[in] data pointer to data to be stored in the list
 * @return pointer to the new head of the list
 */
sll_node_t *sll_insert_head(sll_list_t *list, void *data)
{
    sll_node_t *node;
    node = malloc(sizeof(sll_node_t));
    if (node == NULL) {
        fprintf(stderr, "[ERROR] sll_create_node errno: %d", errno);
        return NULL;
    }
    node->data = data;
    if (list->head == NULL) {
        /* list is empty */
        list->head = node;
        list->tail = node;
        node->next = NULL;
    } else {
        node->next = list->head;
        list->head = node;
    }
    list->length++;
    if (list->max_length < list->length) {
        list->max_length = list->length;
    }
    return node;
}
/**
 * @brief Insert a new node at the tail of the list passed in argument
 * @param[in] list pointer to the list in which add a new node
 * @param[in] data pointer to data to be stored in the list
 * @return pointer to the new tail of the list
 */
sll_node_t *sll_insert_tail(sll_list_t *list, void *data)
{
    sll_node_t *node;
    node = malloc(sizeof(sll_node_t));
    if (node == NULL) {
        fprintf(stderr, "[ERROR] sll_create_node errno: %d", errno);
        return NULL;
    }
    node->data = data;
    if (list->head == NULL) {
        /* list is empty */
        list->head = node;
        list->tail = node;
        node->next = NULL;
    } else {
        node->next = NULL;
            list->tail->next = node;
            list->tail = node;
    }
    list->length++;
    if (list->max_length < list->length) {
        list->max_length = list->length;
    }
    return node;
}

/**
 * @brief Remove a node from the list
 * @param[in] list pointer to the list
 * @param[in] node pointer to the node to remove
 * @return 0 if node is well removed, -1 otherwise
 */
int32_t sll_remove_node(sll_list_t *list, sll_node_t *node)
{
    sll_node_t *current_node;
    current_node = list->head;
    if (current_node == node) {
        /* Remove head */
        list->head = list->head->next;
        if (current_node->next == NULL) {
            /* No node following this one, this is the tail */
            list->tail = list->head;
        }
        free(node->data);
        free(node);
        list->length--;
        return 0;
    } else {
        /* Parse the head to find the right node */
        while ((current_node->next != NULL) && (current_node->next != node)) {
            current_node = current_node->next;
        }
        /* If next is not NULL, next is the node to remove */
        if (current_node->next != NULL) {
            current_node->next=node->next;
            if (current_node->next == NULL) {
            	/* No node following this one, this is the tail */
                list->tail = current_node;
            }
            free(node->data);
            free(node);
            list->length--;
            return 0;
        } else {
            /* Node not found */
            fprintf(stderr, "[ERROR] sll_remove_node errno: %d", EINVAL);
            return -1;
        }
    }
}

/**
 * @brief Apply a function passed as parameter to each node of the list
 * @param[in] list pointer to the list
 * @param[in] apply_fn pointer to the function to apply to the list
 * @param[in] args pointer to arguments passed to the function
 * @return 0 in case of success, -1 otherwise
 * @note the called function is expected to return 0 in case of success
 */
int32_t sll_apply_fn_to_list(sll_list_t *list,
                             int32_t (*apply_fn)(void*, void*),
                             void* args)
{
    sll_node_t *node;
    node = list->head;
    while (node)
    {
        if (apply_fn(node->data, args) != 0) {
            return -1;
        }
        node=node->next;
    }
    return 0;
}

/**
 * @brief Delete the list and release all dynamic memory allocation
 * @param[in] list pointer to the list, set to NULL when the list is deleted
 * @return 0 when finished
 */
int32_t sll_free(sll_list_t *list)
{
    sll_node_t *node = list->head;
    sll_node_t *next_node;
    while (node)
    {
        next_node = node->next;
        if (node->data != NULL) {
            free(node->data);
        }
        free(node);
        node = next_node;
        list->length--;
    }
    printf("sll_free list\n");
    free(list);
    return 0;
}

/**
 * @brief Return the first node (head) of the list
 * @param[in] list pointer to the list
 * @return pointer to the head of the list
 */
sll_node_t *sll_get_head(sll_list_t *list)
{
    return list->head;
}

/**
 * @brief Return the last node (tail) of the list
 * @param[in] list pointer to the list
 * @return pointer to the tail of the list
 */
sll_node_t *sll_get_tail(sll_list_t *list)
{
	return list->tail;
}

/**
 * @brief Find a node in the list
 * @param[in] list pointer to the list
 * @param[in] cmp_fn pointer to the comparison function
 * @param[in] data pointer to the data to find
 * @return pointer to the node if comparison function returned 0, NULL otherwise
 * @note cmp_fn is expected to return 0 in case of the two data are
 * considered identical
 */
sll_node_t *sll_find(sll_list_t *list, int(*cmp_fn)(void*, void*), void *data)
{
    sll_node_t *node;
    if (list != NULL) {
        node = list->head;
        while (node) {
            if (cmp_fn(node->data, data) == 0) {
                //printf("(flow found) nb nodes explored : %d\n",n_elements);
                return node;
            }
            node = node->next;
        }
    }
    return NULL;
}

#undef SINGLY_LINKED_LIST_C
