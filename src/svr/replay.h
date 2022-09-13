/*
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


#ifndef SPA_REPLAY_H
#define SPA_REPLAY_H

// Maximum amount of replay recording hashes that can be stored in memory.
#define SPA_MAX_REPLAY_OBJECTS 8192



// Holds a packet hash and a timestamp.
typedef struct spa_replay_record_t {
    char hash[SPA_PACKET_HASH_SIZE];
    uint64_t time;
} spa_replay_t;



// Monitor to prevent replays.
int SPAReplay__init();
// Record a SHA256 hash into the linked list.
void SPAReplay__add( char* hash, uint64_t* time );
// Check the hash against all valid records after a cleanup.
int SPAReplay__check( char* hash );



#endif   /* SPA_REPLAY_H */
