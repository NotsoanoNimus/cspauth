/*
 * Header definitions for linked lists structures used by the SPA server.
 * Included outside the /svr/ source due to its relation with "spa.h".
 *
 *
 * Copyright (C) 2022 Zachary Puhl - All Rights Reserved.
 *
 * Site: https://github.com/NotsoanoNimus/cspauth
 * Contact: github (..-at-..) xmit (..-dot-..) xyz
 *
 * You may use, distribute, and modify this code according to the terms
 *  of the MIT License, which can be found in the LICENSE text file at
 *  the original 'cspauth' project URL. You should have received a copy
 *  of the MIT License with this file. If not, please send a message via
 *  GitHub to @NotsoanoNimus.
 *
 */


#ifndef HEADER_LINKEDLIST_H
#define HEADER_LINKEDLIST_H



#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>



#define MAX_LIST_NODES 1000000

#define GET_FROM_LIST_AS( list, type, name, propertyoffset, wherevalue, valuesize ) \
	type* name = (type*)((list_get_node(list, propertyoffset, wherevalue, valuesize))->node);



typedef struct spa_linked_list_node_t {
	void* node;
	struct spa_linked_list_node_t* next;
} __attribute__((__packed__)) LIST_NODE;

typedef struct spa_linked_list_t {
	LIST_NODE* head;
	uint32_t max_size;
} __attribute__((__packed__)) LIST;



LIST* new_list();
void destroy_list( LIST* list_obj );
int list_add_node( LIST* list_obj, void* node_obj );
LIST_NODE* list_remove_node( LIST* list_obj, LIST_NODE* node );
uint32_t list_get_count( LIST* list_obj );
LIST_NODE* list_get_node( LIST* list_obj, int node_property_offset, void* property_value, size_t property_size );
LIST_NODE* list_get_head_node( LIST* list_obj );
LIST_NODE* list_get_tail_node( LIST* list_obj );
void clear_list( LIST* list_obj );



#endif
