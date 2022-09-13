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


#ifndef SPA_USERS_H
#define SPA_USERS_H

#include <string.h>

#include "../spa.h"
#include "action.h"



#define MAX_SINGLE_AUTL_STRLEN 64
#define MAX_USERS 128
#define MAX_USER_AUTH_LISTS SPA_MAX_ACTIONS


// Authorization lists should be processed when the daemon starts, _before_ the socket starts to listen for SPAs.
typedef struct spa_user_autl_opt_range_t {
    uint16_t low_bound;
    uint16_t high_bound;
} spa_option_range_t;

typedef struct spa_user_autl_t {
    uint16_t action_id;
    uint8_t any_action;
    uint8_t opt_range_count;
    spa_option_range_t allowed_options[SPA_MAX_OPTS_PER_ACTION];
} spa_autl_t;


// Username to RSA publickey associations.
typedef struct spa_user_pkey_t {
    char key_path[PATH_MAX];
    EVP_PKEY* evp_pkey;
} spa_user_key_t;


// Meta-structure containing data for users.
typedef struct spa_user_data_t {
    char username[SPA_PACKET_USERNAME_SIZE];
    spa_user_key_t pkey;
    spa_autl_t* autl_head;
    List_t* autl;
    uint8_t valid_user;
} spa_user_t;



// User static list functionality (needs to be exported to other svr includes).
spa_autl_t* get_user_head();
uint32_t get_user_count();
spa_user_t* create_user( char* username );
spa_user_t* get_user( char* username );
spa_user_t* get_config_for_user( char* username );
int set_config_for_user( spa_user_t* p_user_data );
void clear_all_users();


// AUTL policy and control functions. Related to users.
// Load user authorizations. Since this is called during config parsing and reload,
//   the service is free to throw an error and halt. Thus, the return type is just void.
int load_user_autls( spa_user_t* p_user_data, char* p_autl_conf_val );
// Dump authorization lists for the user to a file or stream.
int dump_user_autls(spa_user_t* p_user_data, FILE* stream );
// Get whether user has authorization for the action-option combination.
int is_user_authorized( spa_user_t* p_user_data, uint16_t* action_id, uint16_t* option );


// PKEY for user and related functions.
// Load an X509 public key from a filename.
int load_user_pkey( spa_user_t* p_user_data, char* p_pem_filename );
// Get the validity of a pkey without saving/changing anything.
int get_user_pkey( spa_user_t* p_user_data );



#endif   /* SPA_USERS_H */
