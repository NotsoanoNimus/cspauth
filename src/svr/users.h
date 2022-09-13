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
#define SPA_MAX_USERS 128
#define MAX_USER_AUTH_LISTS SPA_MAX_ACTIONS


// Authorization lists should be processed when the daemon starts, _before_ the socket starts to listen for SPAs.
typedef struct spa_user_autl_opt_range_t {
    uint16_t low_bound;
    uint16_t high_bound;
} __attribute__((__packed__)) spa_option_range_t;

typedef struct spa_user_autl_t {
    uint16_t action_id;
    uint8_t any_action;
    uint8_t opt_range_count;
    spa_option_range_t allowed_options[SPA_MAX_OPTS_PER_ACTION];
} __attribute__((__packed__)) spa_autl_t;

// Meta-structure containing data for users.
//   IMPORTANT: The autl_t structure is the same size (64 bits) as any regular array of pointers.
//               So in this case, it's better to just use a heap-based allocation of the SPA_MAX_AUTH_LISTS size
//               rather than doing an indirect pointer array or a linked list.
typedef struct spa_user_data_t {
    char username[SPA_PACKET_USERNAME_SIZE];
    char pkey_path[PATH_MAX];
    EVP_PKEY* pkey;
    void* p_autls;
    uint16_t autl_count;
    uint8_t valid_user;
} spa_user_t;



// User manipulation and retrieval functions.
void SPAUser__init();
void SPAUser__clear();
unsigned long SPAUser__count();
spa_user_t* SPAUser__get_array();
spa_user_t* SPAUser__get();
spa_user_t* SPAUser__add();


// AUTL policy and control functions. Related to users.
// Load user authorizations. Since this is called during config parsing and reload,
//   the service is free to throw an error and halt. Thus, the return type is just void.
int SPAUser__load_autls( spa_user_t* p_user_data, char* p_autl_conf_val );
// Dump authorization lists for the user to a file or stream.
int SPAUser__dump_autls(spa_user_t* p_user_data, FILE* stream );
// Get whether user has authorization for the action-option combination.
int SPAUser__is_authorized( spa_user_t* p_user_data, uint16_t action, uint16_t option );


// PKEY for user and related functions.
// Load an X509 public key from a filename and save it into a user's loaded profile.
int SPAUser__load_pkey( spa_user_t* p_user_data, char* p_pem_filename );
// Get the validity of a pkey without saving/changing anything.
int SPAUser__get_pkey( spa_user_t* p_user_data );



#endif   /* SPA_USERS_H */
