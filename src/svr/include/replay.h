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


#ifndef HEADER_REPLAY_H
#define HEADER_REPLAY_H



#include <unistd.h>
#include <pthread.h>

#include "../../spa.h"



// Maximum amount of replay recording hashes that can be stored in memory.
#define MAX_REPLAY_OBJECTS 8192



typedef struct spa_replay_record_t {
	BYTE hash[SPA_PACKET_HASH_SIZE];
	uint64_t time;
//	struct spa_replay_record_t* next;
} __attribute__((__packed__)) REPLAY_RECORD;



// Monitor to prevent replays.
int prevent_replay_init();
// Record a SHA256 hash into the linked list.
void create_replay_record( BYTE* hash, uint64_t* time );
// Check the hash against all valid records after a cleanup.
int check_for_replay( BYTE* hash );



#endif
