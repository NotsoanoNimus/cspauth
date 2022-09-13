/*
 * Replay-monitor implementations.
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


#include "replay.h"

#include "../spa.h"
#include "log.h"
#include "conf.h"

#include <unistd.h>
#include <pthread.h>



// Holds a packet hash and a timestamp.
typedef struct _spa_replay_record_t {
    char hash[SPA_PACKET_HASH_SIZE];
    uint64_t time;
} spa_replay_record_t;

// Internal linked-list structures exclusive to the replay monitor.
//   Using this will prevent the necessity of allocating some predefined limited array of pointers
//   which can be spammed and overflowed to defeat replay protections.
typedef struct simple_list_node {
    spa_replay_record_t record;
    struct simple_list_node* p_next;
} list_node_t;
typedef struct simple_list {
    list_node_t* p_head;
} list_t;


static list_t hashes;

static int spa_replay_monitor_is_init = OFF;
static unsigned long hashes_count = 0;

static pthread_t spa_replay_monitor_thread;
static pthread_attr_t spa_replay_monitor_thread_attributes;
static pthread_mutex_t spa_replay_record_lock = PTHREAD_MUTEX_INITIALIZER;



// Drop all records from memory which are older than now minus the validity window.
//   THIS SHOULD ALWAYS BE RUN BEFORE QUERYING ANY RECORDS.
static void* _spa_replay_record_cleanup( void* nonce ) {
    while ( 1 ) {
        pthread_mutex_lock( &spa_replay_record_lock );

# ifdef DEBUG
    __debuglog(
        printf( " ***** (REPLAY MONITOR TICK - WATCHING '%lu' HASHES) *****\n", hashes_count );
    )
# endif

        // Get the current timestampe.
        time_t now;
        time( &now );
        uint64_t epoch_time = (uint64_t)now;

        list_node_t* p_current = hashes.p_head;
        if ( NULL == p_current )
            goto spa_replay_continue_monitor;

        int iteration = 1;

        while ( NULL != p_current ) {
            spa_replay_record_t* p_node = &(p_current->record);
            if ( NULL == p_node )  continue;

            // Check if the entry is stale. If so, remove it; else, continue.
            if ( p_node->time <= (epoch_time - ((uint64_t)(spa_conf.validity_window & 0x00000000FFFFFFFF))) ) {
# ifdef DEBUG
                __debuglog(
                    printf( " ***** (MONITOR STACK: FREEING STALE ENTRY AT '%d' OF '%lu' RECORDS) *****\n",
                        iteration, hashes_count );
                )
# endif

                __debuglog(
                    char sigtohex[(SPA_PACKET_HASH_SIZE*2) + 1];
                    memset( sigtohex, 0, (SPA_PACKET_HASH_SIZE*2)+1 );

                    for ( int i = 0; i < SPA_PACKET_HASH_SIZE; i++ )
                        snprintf(  &sigtohex[i*2], 3, "%02x", (unsigned int)p_node->hash[i]  );
                    sigtohex[SPA_PACKET_HASH_SIZE*2] = '\0';

                    printf( " ***** [%lu] MONITOR: Releasing monitored packet hash '[...]%s' from time"
                        " '%lu'. *****\n", epoch_time, &sigtohex[(SPA_PACKET_HASH_SIZE*2)-12], p_node->time );
                )

                // Iterate the linked list until the p_current node is next in line.
                list_node_t* p_tmp = hashes.p_head;
                while (
                       NULL != p_tmp
                    && p_tmp != p_current
                    && p_tmp->p_next != p_current
                    && NULL != p_tmp->p_next
                )  p_tmp = p_tmp->p_next;

                if ( p_tmp == p_current && hashes.p_head == p_current ) {
                    hashes.p_head = p_current->p_next;
                    free( p_current );
                    p_current = hashes.p_head;

                    hashes_count--;
                    continue;
                } else {
                    // Bridge the gap to the next node in the list.
                    p_tmp->p_next = p_current->p_next;

                    list_node_t* p_shadow = p_current->p_next;
                    free( p_current );
                    p_current = p_shadow;

                    hashes_count--;
                }

            } else {
                iteration++;
            }

            // Next list item.
            p_current = p_current->p_next;
        }

        // Function that unlocks the mutex and waits so as to not burn CPU cycles.
        spa_replay_continue_monitor:
            pthread_mutex_unlock( &spa_replay_record_lock );
            sleep( MIN_VALIDITY_WINDOW );
    }

    // This should never be reached, but the compiler cries because void* :)
    return NULL;
}



// ========== "PUBLIC" METHODS IN HEADER FILE ==========

// Spawn a lone thread responsible for keeping the replay_record memory "db" clean.
int SPAReplay__init() {
    if ( OFF != spa_replay_monitor_is_init ) {
        write_error_log( "The replay monitor thread has already been initialized.\n", NULL );
    }

    // Initial value of NULL (empty list).
    hashes.p_head = NULL;

    // Initialize a new monitor thread and set it to detached.
    pthread_attr_init( &spa_replay_monitor_thread_attributes );
    pthread_attr_setdetachstate( &spa_replay_monitor_thread_attributes, 1 );

    int rc = pthread_create(
        &spa_replay_monitor_thread,
        &spa_replay_monitor_thread_attributes,
        _spa_replay_record_cleanup,
        NULL
    );

    // Failure if return code is not 0.
    if ( 0 != rc )
        return EXIT_FAILURE;

    // Free resources and set that the thread was init'd.
    pthread_attr_destroy( &spa_replay_monitor_thread_attributes );
    spa_replay_monitor_is_init = ON;

    // OK.
    return EXIT_SUCCESS;
}



// Add a replay record to the linked list (wrapper function.
void SPAReplay__add( char* hash, uint64_t time ) {
    pthread_mutex_lock( &spa_replay_record_lock );

    list_node_t* p_new = (list_node_t*)calloc( 1, sizeof(list_node_t) );

    memcpy( &((p_new->record).hash), hash, SPA_PACKET_HASH_SIZE );
    (p_new->record).time = time;

    // Set the next ptr to the old HEAD and set the HEAD to the newly alloc'd item. Quick insertion.
    p_new->p_next = hashes.p_head;
    hashes.p_head = p_new;

    hashes_count++;
    pthread_mutex_unlock( &spa_replay_record_lock );
}



// Check the hash against all valid records in the replays linked list.
int SPAReplay__check( char* hash ) {
    pthread_mutex_lock( &spa_replay_record_lock );

    int exit_code = EXIT_SUCCESS;
    list_node_t* p_node = hashes.p_head;
    if ( NULL == p_node )
        goto __end_replay_records_check;

    spa_replay_record_t* p_current = &(p_node->record);

# ifdef DEBUG
__debuglog(
    printf( " `---> Checking SPA packet CURRENT hash for replay with hex:\n" );
    print_hex( &hash[0], SPA_PACKET_HASH_SIZE );
)
# endif

    if ( NULL != p_current ) {
        do {

# ifdef DEBUG
__debuglog(
    printf( " `------> Against hash with hex:\n" );
    print_hex( &(p_current->hash[0]), SPA_PACKET_HASH_SIZE );
)
# endif

            for ( int i = 0; i < SPA_PACKET_HASH_SIZE; i++ ) {
                if ( p_current->hash[i] != hash[i] )
                    goto __next_replay_record;
            }

# ifdef DEBUG
__debuglog(
    printf( "Found matching hash with timestamp '%lu'. Hexdump:\n", p_current->time );
    print_hex( &(p_current->hash[0]), SPA_PACKET_HASH_SIZE );
    print_hex( &hash[0], SPA_PACKET_HASH_SIZE );
)
# endif

            exit_code = EXIT_FAILURE;  // if all hash bytes match, return problem status since a replay is detected
            goto __end_replay_records_check;

            __next_replay_record:
                continue;

        } while ( NULL != (p_node = p_node->p_next) );
    }

    __end_replay_records_check:
        pthread_mutex_unlock( &spa_replay_record_lock );
        return exit_code;
}
