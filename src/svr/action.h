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


#ifndef SPA_ACTION_H
#define SPA_ACTION_H



#include <arpa/inet.h>

#include "../../spa.h"



#define SPA_MAX_ACTIONS 1024
#define SPA_MAX_OPTS_PER_ACTION 29
#define SPA_SPA_MAX_ACTION_CMD_LEN 254
#define SPA_MAX_ACTION_SUBSTITUTIONS 128



// Actions are processed when the daemon starts.
typedef struct spa_action_t {
    uint16_t action_id;
    char command[SPA_SPA_MAX_ACTION_CMD_LEN];
} spa_action_t;



struct spa_packet_data_replacement_t {
    char before;
    char after;
};

struct spa_dynamic_substitutions_t {
    struct spa_packet_data_replacement_t list[SPA_MAX_ACTION_SUBSTITUTIONS];
    uint16_t count;
} spa_char_subs;



size_t SPAAction__count();
void SPAAction__clear();
spa_action_t* SPAAction__get( uint16_t action );
spa_action_t* SPAAction__add( uint16_t action, const char* p_command );
int SPAAction__perform(
    spa_action_t* p_action,
    spa_packet_meta_t* p_packet_meta,
    sa_family_t* listen_family
);



#endif   /* SPA_ACTION_H */
