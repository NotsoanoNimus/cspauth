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


#ifndef HEADER_ACTION_H
#define HEADER_ACTION_H



#include <arpa/inet.h>

#include "../../spa.h"



#define MAX_ACTIONS 1024
#define MAX_ALLOWABLE_OPTS_PER_ACTION 29
#define MAX_ACTION_CMD_LEN 254
#define SPA_MAX_ACTION_SUBSTITUTIONS 128



// Actions are processed when the daemon starts.
typedef struct spa_action_t {
	uint16_t action_id;
	BYTE command[MAX_ACTION_CMD_LEN];
	struct spa_action_t* next;
} __attribute__((__packed__)) ACTION;



struct spa_packet_data_replacement_t {
	BYTE before;
	BYTE after;
};

struct spa_dynamic_substitutions_t {
	struct spa_packet_data_replacement_t list[SPA_MAX_ACTION_SUBSTITUTIONS];
	uint16_t count;
} __attribute__((__packed__)) spa_char_subs;



// Linked list functions.
uint32_t get_actions_count();
ACTION* get_action_by_id( uint16_t* p_action );
void clear_all_actions();
ACTION* create_action( uint16_t* p_action, BYTE* command );

// Action-related functions.
int perform_action( ACTION* p_action,
	struct spa_packet_meta_t* p_packet_meta, sa_family_t* listen_family );
int substitute_packet_data( BYTE* p_action_str );



#endif
