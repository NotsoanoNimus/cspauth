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


#ifndef USERS_HEADER_H
#define USERS_HEADER_H



#include <string.h>

#include "../../spa.h"
#include "action.h"



#define MAX_SINGLE_AUTL_STRLEN 64
#define MAX_USERS 128
#define MAX_USER_AUTH_LISTS MAX_ACTIONS


// Authorization lists should be processed when the daemon starts, _before_ the socket starts to listen for SPAs.
typedef struct spa_user_autl_opt_range_t {
	uint16_t low_bound;
	uint16_t high_bound;
} __attribute__((__packed__)) OPTRANGE;

typedef struct spa_user_autl_t {
	uint16_t action_id;
	uint8_t any_action;
	uint8_t opt_range_count;
	OPTRANGE allowed_options[MAX_ALLOWABLE_OPTS_PER_ACTION];
} __attribute__((__packed__)) AUTL;


// Username to RSA publickey associations.
typedef struct spa_user_pkey_t {
	BYTE key_path[PATH_MAX];
	EVP_PKEY* evp_pkey;
} __attribute__((__packed__)) USERPKI;


// Meta-structure containing data for users.
typedef struct spa_user_data_t {
	BYTE username[SPA_PACKET_USERNAME_SIZE];
	USERPKI pkey;
	AUTL* autl_head;
	LIST* autl;
	uint8_t valid_user;
} __attribute__((__packed__)) USER;



// User static list functionality (needs to be exported to other svr includes).
LIST_NODE* get_user_head();
uint32_t get_user_count();
USER* create_user( BYTE* username );
USER* get_user( BYTE* username );
USER* get_config_for_user( BYTE* username );
int set_config_for_user( USER* p_user_data );
void clear_all_users();


// AUTL policy and control functions. Related to users.
// Load user authorizations. Since this is called during config parsing and reload,
//   the service is free to throw an error and halt. Thus, the return type is just void.
int load_user_autls( USER* p_user_data, char* p_autl_conf_val );
// Dump authorization lists for the user to a file or stream.
int dump_user_autls( USER* p_user_data, FILE* stream );
// Get whether user has authorization for the action-option combination.
int is_user_authorized( USER* p_user_data, uint16_t* action_id, uint16_t* option );



#endif
