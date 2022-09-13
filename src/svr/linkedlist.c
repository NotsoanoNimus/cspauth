/*
 * Linked-list structure implementations. Used broadly in a few different
 *  server application locations.
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


#include "../linkedlist.h"



LIST_NODE* list_get_head_node( LIST* list_obj ) {
    if ( list_obj == NULL )  return NULL;
    return list_obj->head;
}

void __list_set_head_node( LIST* list_obj, LIST_NODE* val ) {
    if ( list_obj == NULL )  return;
    list_obj->head = val;
}

LIST_NODE* list_get_tail_node( LIST* list_obj ) {
    LIST_NODE* x = list_get_head_node( list_obj );
    int loop_stop = 0;
    while ( x != NULL && loop_stop < MAX_LIST_NODES ) {
        if ( x->next == NULL )  return x;
        x = x->next;
        loop_stop++;
    }
    return NULL;
}



LIST* new_list( uint32_t max_size ) {
    // This never needs to be freed, for CSPAuth/D use at least. Just the nodes using 'clear_list'.
    LIST* x = (LIST*)malloc( sizeof(LIST) );
    x->head = NULL;
    x->max_size = max_size;
    return x;
}

void destroy_list( LIST* list_obj ) {
    clear_list( list_obj );
    if ( list_obj != NULL )  free( list_obj );
}



int list_add_node( LIST* list_obj, void* node_obj ) {
    if ( list_obj == NULL || node_obj == NULL )  return EXIT_FAILURE;

    if ( list_get_count( list_obj ) >= list_obj->max_size )  return EXIT_FAILURE;

    // Allocate space according to the node size and set the properties.
    LIST_NODE* x = (LIST_NODE*)malloc( sizeof(LIST_NODE) );
    memset( x, 0, sizeof(LIST_NODE) );
    x->node = node_obj;
    x->next = list_get_head_node( list_obj );
    __list_set_head_node( list_obj, x );

    return EXIT_SUCCESS;
}



// Returns a pointer to the previous list node, or NULL on error or empty list.
LIST_NODE* list_remove_node( LIST* list_obj, LIST_NODE* node ) {
    if ( list_obj == NULL || node == NULL )  return NULL;

    LIST_NODE* x = list_get_head_node( list_obj );
    if ( x == NULL ) {
        // Empty list; nothing to remove.
        return NULL;
    } else if ( x == node && x->next == NULL ) {
        // When the node to remove is the only list item, free it and set head to null.
        free( node );
        __list_set_head_node( list_obj, NULL );
        return NULL;
    }

    // Automatically move to the next node after pointing the 'shadow' to the head node.
    LIST_NODE* prev_node = list_get_head_node( list_obj );
    x = x->next;
    while ( x != NULL ) {
        if ( x == node ) {
            // Point the previous node to the next node, thereby briding OVER this list item and removing it.
            prev_node->next = x->next;
            free( x );
            return prev_node;
        }
        prev_node = x;
        x = x->next;
    }

    // If nothing was found matching the list node address provided, exit failure.
    return NULL;
}



uint32_t list_get_count( LIST* list_obj ) {
    uint32_t count = 0;
    for ( LIST_NODE* x = list_get_head_node( list_obj ); x != NULL; x = x->next )  count++;
    return count;
}



LIST_NODE* list_get_node( LIST* list_obj, int node_property_offset, void* property_value, size_t property_size ) {
    if ( property_value == NULL || property_size <= 0 )  return NULL;

    for ( LIST_NODE* x = list_get_head_node( list_obj ); x != NULL; x = x->next ) {
        if ( memcmp( ((x->node)+node_property_offset), property_value, property_size ) == 0 )  return x;
    }

    return NULL;
}



void clear_list( LIST* list_obj ) {
    if ( list_obj == NULL )  return;

    LIST_NODE* x = list_get_head_node( list_obj );
    while ( x != NULL ) {
        LIST_NODE* x_shadow = x->next;
        if ( x->node != NULL )  free( x->node );
        free( x );
        x = x_shadow;
    }

    __list_set_head_node( list_obj, NULL );
}
