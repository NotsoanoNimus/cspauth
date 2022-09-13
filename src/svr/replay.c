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



LIST* replays_list = NULL;
int __spa_replay_monitor_is_init = OFF;

pthread_t __spa_replay_monitor_thread;
pthread_attr_t __spa_replay_monitor_thread_attributes;
pthread_mutex_t __spa_replay_record_lock = PTHREAD_MUTEX_INITIALIZER;



// Push a new hash onto the beginning of the stack.
void _spa_replay_record_push( BYTE* hash, uint64_t* time ) {
    malloc_sizeof( REPLAY_RECORD, new_head );

    memcpy( &new_head->hash, hash, SPA_PACKET_HASH_SIZE );
    memcpy( &new_head->time, time, sizeof(uint64_t) );

    list_add_node( replays_list, new_head );
}



// Drop all records from memory which are older than now minus the validity window.
//   THIS SHOULD ALWAYS BE RUN BEFORE QUERYING ANY RECORDS.
void* _spa_replay_record_cleanup( void* nonce ) {
    while ( 1 ) {
        pthread_mutex_lock( &__spa_replay_record_lock );

# ifdef DEBUG
__debuglog( printf( " ***** (REPLAY MONITOR TICK - WATCHING '%d' HASHES) *****\n", list_get_count( replays_list ) ); )
# endif

        time_t now;
        time( &now );
        uint64_t epoch_time = (uint64_t)now;

        LIST_NODE* current = list_get_head_node( replays_list );
        if ( current == NULL )  goto __spa_replay_continue_monitor;
        int iteration = 1;

        while ( current != NULL ) {
            REPLAY_RECORD* current_node = ((REPLAY_RECORD*)(current->node));
            if ( current_node == NULL )  continue;

            if ( current_node->time <= (epoch_time - ((uint64_t)(spa_conf.validity_window & 0x00000000FFFFFFFF))) ) {
# ifdef DEBUG
__debuglog(
    printf( " ***** (MONITOR STACK: FREEING STALE ENTRY AT '%d' OF '%d' RECORDS) *****\n", iteration, list_get_count( replays_list ) );
)
# endif
                __debuglog(
                    char sigtohex[(SPA_PACKET_HASH_SIZE*2) + 1];
                    memset( sigtohex, 0, (SPA_PACKET_HASH_SIZE*2)+1 );
                    for ( int i = 0; i < SPA_PACKET_HASH_SIZE; i++ )
                        snprintf( &sigtohex[i*2], 3, "%02x", (unsigned int)current_node->hash[i] );
                    sigtohex[SPA_PACKET_HASH_SIZE*2] = '\0';
                    printf( " ***** [%lu] MONITOR: Releasing monitored packet hash '[...]%s' from time"
                        " '%lu'. *****\n", epoch_time, &sigtohex[(SPA_PACKET_HASH_SIZE*2)-12], current_node->time );
                )

                LIST_NODE* prev_node = list_remove_node( replays_list, current );
                if ( prev_node == NULL && list_get_count( replays_list ) > 0 ) {
                    prev_node = list_get_head_node( replays_list );
                } else if ( prev_node == NULL )  break;
                current = prev_node->next;
            } else {
                current = current->next;
                iteration++;
            }
        }

        __spa_replay_continue_monitor:
            pthread_mutex_unlock( &__spa_replay_record_lock );

            sleep( MIN_VALIDITY_WINDOW );
    }
}



// ========== "PUBLIC" METHODS IN HEADER FILE ==========

// Spawn a lone thread responsible for keeping the replay_record memory "db" clean.
int prevent_replay_init() {
    if ( __spa_replay_monitor_is_init != OFF ) {
        write_error_log( "The replay monitor thread has already been initialized.\n", NULL );
    }

    replays_list = new_list( UINT64_MAX - 1 );

    pthread_attr_init( &__spa_replay_monitor_thread_attributes );
    pthread_attr_setdetachstate( &__spa_replay_monitor_thread_attributes, 1 );

    int rc = pthread_create( &__spa_replay_monitor_thread,
        &__spa_replay_monitor_thread_attributes, _spa_replay_record_cleanup, NULL );
    if ( rc != 0 )  return EXIT_FAILURE;

    pthread_attr_destroy( &__spa_replay_monitor_thread_attributes );
    __spa_replay_monitor_is_init = ON;

    return EXIT_SUCCESS;
}

// Record a SHA256 hash into the linked list.
void create_replay_record( BYTE* hash, uint64_t* time ) {
    pthread_mutex_lock( &__spa_replay_record_lock );

    _spa_replay_record_push( hash, time );

    pthread_mutex_unlock( &__spa_replay_record_lock );
}

// Check the hash against all valid records in the replays linked list.
int check_for_replay( BYTE* hash ) {
    pthread_mutex_lock( &__spa_replay_record_lock );

    int exit_code = EXIT_SUCCESS;
    LIST_NODE* current_node = list_get_head_node( replays_list );
    if ( current_node == NULL )  goto __end_replay_records_check;
    REPLAY_RECORD* current = ((REPLAY_RECORD*)(current_node->node));

# ifdef DEBUG
__debuglog(
    printf( " `---> Checking SPA packet CURRENT hash for replay with hex:\n" );
    print_hex( &hash[0], SPA_PACKET_HASH_SIZE );
)
# endif

    if ( current != NULL ) {
        do {

# ifdef DEBUG
__debuglog(
    printf( " `------> Against hash with hex:\n" );
    print_hex( &current->hash[0], SPA_PACKET_HASH_SIZE );
)
# endif

            for ( int i = 0; i < SPA_PACKET_HASH_SIZE; i++ ) {
                if ( current->hash[i] != hash[i] )  goto __next_replay_record;
                // didn't want to do a break here; TODO: too ambiguous?
            }

# ifdef DEBUG
__debuglog(
    printf( "Found matching hash with timestamp '%lu'. Hexdump:\n", current->time );
    print_hex( &current->hash[0], SPA_PACKET_HASH_SIZE );
    print_hex( &hash[0], SPA_PACKET_HASH_SIZE );
)
# endif

            exit_code = EXIT_FAILURE;  // if all hash bytes match, return problem status since a replay is detected
            goto __end_replay_records_check;

            __next_replay_record:
                continue;
        } while ( (current_node = current_node->next) != NULL );
    }

    __end_replay_records_check:
        pthread_mutex_unlock( &__spa_replay_record_lock );
        return exit_code;
}
