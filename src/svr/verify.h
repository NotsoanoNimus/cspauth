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


#ifndef SPA_VERIFY_H
#define SPA_VERIFY_H

#include "../spa.h"
#include "users.h"
#include "action.h"



/*
 * Process for authenticating and authorizing an incoming SPA packet:
 *   1 - Check the timestamp. Is the time within the configured validity window according to the server time?
 *   2 - Validate the username. Make sure they exist and are not marked invalid.
 *      2.5 - Get the user's loaded configuration settings.
 *   3 - Hash the packet locally and make sure it matches the packet hash.
 *      3.5 - Make sure this isn't a replay (see replay implementations).
 *   4 - Check whether the requested action is loaded in the running configuration.
 *   5 - See if the user is authorized to perform the action.
 *   6 - See if the user has a valid and loaded public key.
 *   7 - Authenticate the signature on the packet using the public key.
 *   8 - Authorize and perform the requested action.
 *
 * All processing functions listed will accept a packet_id pointer so logging continuity can be followed easily.
 *
 */

int pre_packet_verify( char* input_buffer );
int verify_timestamp( uint64_t* packet_id, uint64_t* timestamp );
int verify_username( uint64_t* packet_id, char* username );
int verify_packet_hash( uint64_t* packet_id, struct spa_packet_t* p_spa_packet );
int verify_action( uint64_t* packet_id, spa_action_t* p_spa_action, uint16_t* p_action );
int verify_authorization( uint64_t* packet_id, spa_user_t* p_user_data, uint16_t* p_action, uint16_t* p_option );
int verify_pubkey( uint64_t* packet_id, spa_user_t* p_user_data );
int verify_signature( uint64_t* packet_id, struct spa_packet_t* p_spa_packet, spa_user_t* p_user_data );



#endif   /* SPA_VERIFY_H */
