/*
 * Action structures and related functions.
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


#include "include/action.h"
#include "include/conf.h"
#include "include/log.h"


// Use a static-scoped runtime linked list that's refreshed as needed.
LIST* actions_list = NULL;



uint32_t get_actions_count() {
	return list_get_count( actions_list );
}



ACTION* get_action_by_id( uint16_t* p_action ) {
	if ( get_config_flag( SPA_CONF_FLAG_GENERIC_ACTION ) == EXIT_SUCCESS ) {
		__debuglog( write_log( "+++ Skipping action ID check: generic_action is set, so returning that.\n", NULL ); )
		return &(spa_conf.generic_action);
	}

	if ( actions_list == NULL || get_actions_count() <= 0 )  return NULL;

	LIST_NODE* p_list_item = (LIST_NODE*)(list_get_node(actions_list, 0, p_action, sizeof(uint16_t)));
	return p_list_item == NULL ? NULL : ((ACTION*)(p_list_item->node));
}



void clear_all_actions() {
	if ( actions_list != NULL )  destroy_list( actions_list );
	actions_list = new_list( MAX_ACTIONS );
}



ACTION* create_action( uint16_t* p_action_id, BYTE* command ) {
	if ( get_config_flag( SPA_CONF_FLAG_GENERIC_ACTION ) == EXIT_SUCCESS ) {
		write_syslog( LOG_WARNING, "WARNING: Ignoring action with ID %d because"
			" the generic_action option is set.\n", *p_action_id );
		return NULL;
	}

	// Finally, create the object in the heap and push it into the linked list.
	malloc_sizeof( ACTION, p_action );

	p_action->action_id = (uint16_t)(*p_action_id & 0xFFFF);
	memcpy( &p_action->command[0], command, strlen((const char*)command) );
	p_action->command[MAX_ACTION_CMD_LEN-1] = '\0';

	list_add_node( actions_list, p_action );
	return p_action;
}



// Actually perform the requested action/option combination.
#define __SPA_EXP_ACTION_MAX_STRLEN 1024
BYTE* __spa_action_get_token_value( const char* token_name,
	struct spa_packet_meta_t* p_packet_meta, sa_family_t* listen_family );

int perform_action( ACTION* p_action, struct spa_packet_meta_t* p_packet_meta, sa_family_t* listen_family ) {
	if ( spa_char_subs.count > 0 ) {
		if ( substitute_packet_data( p_packet_meta->packet.packet_data ) != EXIT_SUCCESS ) {
			__normallog(
				packet_syslog( p_packet_meta->packet_id, LOG_WARNING, "WARNING: There was a"
					" problem sanitizing the UNSAFE_DATA token expansion.\n", NULL );
			)
			return EXIT_FAILURE;
		}
	}

	BYTE* p_exp_action = (BYTE*)malloc( __SPA_EXP_ACTION_MAX_STRLEN );
	memset( p_exp_action, 0, __SPA_EXP_ACTION_MAX_STRLEN );
	memcpy( p_exp_action, p_action->command, strnlen((const char*)p_action->command,MAX_ACTION_CMD_LEN) );
	p_exp_action[MAX_ACTION_CMD_LEN] = '\0';   // force null-term


	// =========================================================================
	// Replace the tokens within the action's command with their dynamic values.

	const char* tokens[] = { "[[OPTION]]", "[[ACTION]]", "[[USER]]", "[[SRCIP]]", "[[IPFAM]]",
		"[[SRCPT]]", "[[TIME]]", "[[UNSAFE_DATA]]" };
	BYTE* __p_exp_action_tmp = (BYTE*)malloc( __SPA_EXP_ACTION_MAX_STRLEN );

	for ( size_t i = 0; i < sizeof(tokens)/sizeof(*tokens); i++ ) {
		__debuglog( packet_log( p_packet_meta->packet_id, "Expanding action token: '%s'\n", tokens[i] ); )

		// Each time the loop starts, the updated action string should be copied in.
		memset( __p_exp_action_tmp, 0, __SPA_EXP_ACTION_MAX_STRLEN );
		//memcpy( __p_exp_action_tmp, p_exp_action, __SPA_EXP_ACTION_MAX_STRLEN );

		// Iterate the updated action string for occurrences of the current token. Found tokens
		//   get inflated into the temp string.
		BYTE* p_save = &p_exp_action[0];
		for ( BYTE* ptr = &p_exp_action[0]; *ptr != (BYTE)'\0'; ptr += sizeof(BYTE) ) {
			// Exit the loop if the strlen plus the token width exceeds the string bounds from the orig cmd.
			int token_len = strnlen( (const char*)tokens[i], 16 );
			if ( (ptr + token_len) > &p_exp_action[MAX_ACTION_CMD_LEN-1] )  break;

			if ( strncmp( (const char*)ptr, tokens[i], token_len ) == 0 ) {
# ifdef DEBUG
__debuglog( packet_log( p_packet_meta->packet_id, " `---> Action found token '%s' at pos %d.\n",
	tokens[i], (ptr-&p_exp_action[0]) ); )
# endif
				// Append the part of the original string from the save ptr, up to the token.
				strncat( (char*)__p_exp_action_tmp, (char*)p_save, (ptr-p_save) );

				// Get the expanded content and append it.
				BYTE* p_expansion = __spa_action_get_token_value(
					(const char*)tokens[i], p_packet_meta, listen_family );

				if ( p_expansion == NULL ) {
					free( p_exp_action );
					free( __p_exp_action_tmp );
					__normallog(
						packet_syslog( p_packet_meta->packet_id, LOG_WARNING, "WARNING: The expanded action string"
							" was either invalid (unsafe-data) or the token type was somehow incorrect.\n", NULL );
					)
					return EXIT_FAILURE;
				}

				if ( (strnlen( (const char*)__p_exp_action_tmp, __SPA_EXP_ACTION_MAX_STRLEN+1 )
						+ strnlen( (const char*)p_expansion, SPA_PACKET_DATA_SIZE+1 )) > __SPA_EXP_ACTION_MAX_STRLEN ) {
					// Bounds exceeded for the string. Don't perform the action.
					free( p_exp_action );
					free( __p_exp_action_tmp );
					free( p_expansion );
					__normallog(
						packet_syslog( p_packet_meta->packet_id, LOG_WARNING, "WARNING: The expanded action"
							" string tried to write out-of-bounds. Failing action.\n", NULL );
					)
					return EXIT_FAILURE;
				}
				strncat ( (char*)__p_exp_action_tmp, (char*)p_expansion, SPA_PACKET_DATA_SIZE );

				// Jump over the token by strlen and set the new save ptr.
				ptr += token_len;
				p_save = ptr;

				free( p_expansion );
			}
		}

		// Finally, push the final part of the string on and len-check it once again.
		if ( (strnlen( (const char*)__p_exp_action_tmp, __SPA_EXP_ACTION_MAX_STRLEN+1 )
			+ strnlen( (const char*)p_save, __SPA_EXP_ACTION_MAX_STRLEN+1 )) > __SPA_EXP_ACTION_MAX_STRLEN ) {
					// Bounds exceeded for the string. Don't perform the action.
					free( p_exp_action );
					free( __p_exp_action_tmp );
					__normallog(
						packet_syslog( p_packet_meta->packet_id, LOG_WARNING, "WARNING: The expanded action"
							" string tried to write out-of-bounds. Failing action.\n", NULL );
					)
					return EXIT_FAILURE;
		}
		strncat( (char*)__p_exp_action_tmp, (char*)p_save, __SPA_EXP_ACTION_MAX_STRLEN );

		// ... And when the loop finalizes, the updated/expanded string overwrites the original buffer.
		memset( p_exp_action, 0, __SPA_EXP_ACTION_MAX_STRLEN );
		memcpy( p_exp_action, __p_exp_action_tmp, __SPA_EXP_ACTION_MAX_STRLEN );
	}

	// At long last, update the original action string.
	memcpy( p_exp_action, __p_exp_action_tmp, __SPA_EXP_ACTION_MAX_STRLEN );
	p_exp_action[__SPA_EXP_ACTION_MAX_STRLEN - 1] = '\0';   // force null-term
	free( __p_exp_action_tmp );

	// =========================================================================
	// =========================================================================


	__debuglog( packet_log( p_packet_meta->packet_id,
		"Performing expanded action string: <<<|%s|>>>\n", p_exp_action ); )

	int rc = system( (const char*)p_exp_action );
	if ( get_config_flag( SPA_CONF_FLAG_LOG_EXIT_CODES ) == EXIT_SUCCESS ) {
		packet_syslog(
			p_packet_meta->packet_id,
			( rc == 0 ) ? LOG_NOTICE : LOG_WARNING,
			"%s: action <<<|%s|>>> returned exit code '%d'.\n",
			(( rc == 0 ) ? "NOTICE" : "WARNING"), p_exp_action, rc
		);
	} else if ( rc != 0 ) {
		__normallog(
			packet_syslog( p_packet_meta->packet_id, LOG_WARNING,
				"WARNING: performed action returned non-zero exit code '%d'.\n", rc );
		)
	}

	free( p_exp_action );
	return (rc != 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}



// Token expansions from packet meta info.
BYTE*  __spa_action_get_token_value( const char* token_name,
		struct spa_packet_meta_t* p_packet_meta, sa_family_t* listen_family ) {
	// The expanded data can be _AT MOST_ the size of the UNSAFE_DATA expansion.
	BYTE* p_expanded_token = (BYTE*)malloc( SPA_PACKET_DATA_SIZE+1 );
	memset( &p_expanded_token[0], 0, SPA_PACKET_DATA_SIZE+1 );

	// Only forced validation is that the string is NOT printing control characters.
	if ( strcmp( token_name, "[[OPTION]]" ) == 0 ) {
		sprintf( (char*)&p_expanded_token[0], "%d", p_packet_meta->packet.request_option );

	} else if ( strcmp( token_name, "[[ACTION]]" ) == 0 ) {
		sprintf( (char*)&p_expanded_token[0], "%d", p_packet_meta->packet.request_action );

	} else if ( strcmp( token_name, "[[USER]]" ) == 0 ) {
		snprintf( (char*)&p_expanded_token[0], SPA_PACKET_USERNAME_SIZE, "%s",
			(const char*)p_packet_meta->packet.username );
		p_expanded_token[SPA_PACKET_USERNAME_SIZE] = '\0';

	} else if ( strcmp( token_name, "[[SRCIP]]" ) == 0 ) {
		char client_addr[INET6_ADDRSTRLEN];
		memset( &client_addr[0], 0, INET6_ADDRSTRLEN );
		if ( *listen_family == AF_INET ||  (
				(get_config_flag( SPA_CONF_FLAG_NO_IPV4_MAPPING ) == EXIT_SUCCESS) &&
				(IN6_IS_ADDR_V4MAPPED(&(p_packet_meta->clientaddr.sin6_addr)))
		)  ) {
			__debuglog( packet_log( p_packet_meta->packet_id, "*** Shrinking clientaddr to IPv4 sockaddr.\n", NULL ); )
			malloc_sizeof( struct sockaddr_in, p_ip4 );
			p_ip4->sin_family = AF_INET;
			p_ip4->sin_port = p_packet_meta->clientaddr.sin6_port;
			memcpy( &p_ip4->sin_addr, &p_packet_meta->clientaddr.sin6_addr.s6_addr[12], 4 );
			if ( (inet_ntop( AF_INET, &p_ip4->sin_addr, client_addr, INET_ADDRSTRLEN )) == NULL ) {
				__debuglog( packet_log( p_packet_meta->packet_id, "***** Unable to get SRCIP (v4) expansion.\n", NULL ); )
				free( p_expanded_token );
				free( p_ip4 );
				return NULL;
			}
			free( p_ip4 );
		} else {
			__debuglog( packet_log( p_packet_meta->packet_id, "*** Using clientaddr as IPv6 sockaddr.\n", NULL ); )
			if ( (inet_ntop( AF_INET6, &p_packet_meta->clientaddr.sin6_addr, client_addr, INET6_ADDRSTRLEN )) == NULL ) {
				__debuglog( packet_log( p_packet_meta->packet_id, "***** Unable to get SRCIP (v6) expansion.\n", NULL ); )
				free( p_expanded_token );
				return NULL;
			}
		}
		snprintf( (char*)&p_expanded_token[0], INET6_ADDRSTRLEN+1, "%s", client_addr );
		p_expanded_token[INET6_ADDRSTRLEN] = '\0';

	} else if ( strcmp( token_name, "[[IPFAM]]" ) == 0 ) {
		p_expanded_token[0] = ( *listen_family == AF_INET ) ? '4' : '6';
		p_expanded_token[1] = '\0';

	} else if ( strcmp( token_name, "[[SRCPT]]" ) == 0 ) {
		sprintf( (char*)&p_expanded_token[0], "%d", p_packet_meta->clientaddr.sin6_port );

	} else if ( strcmp( token_name, "[[TIME]]" ) == 0 ) {
		sprintf( (char*)&p_expanded_token[0], "%lu", p_packet_meta->packet.client_timestamp );

	} else if ( strcmp( token_name, "[[UNSAFE_DATA]]" ) == 0 ) {
		snprintf( (char*)&p_expanded_token[0], SPA_PACKET_DATA_SIZE, "%s", p_packet_meta->packet.packet_data );
		p_expanded_token[SPA_PACKET_DATA_SIZE-1] = '\0';

	} else {
		// u wot m8
		__debuglog( packet_log( p_packet_meta->packet_id, "Token name '%s' is not valid.\n", token_name ); )
		free( p_expanded_token );
		return NULL;
	}

	p_expanded_token[SPA_PACKET_DATA_SIZE] = '\0';   // force null-term
	return &p_expanded_token[0];
}



int substitute_packet_data( BYTE* p_action_str ) {
# ifdef DEBUG
__debuglog(
	printf( "Packet Data hexdump BEFORE:\n" );
	print_hex( p_action_str, SPA_PACKET_DATA_SIZE );
)
# endif

	for ( int i = 0; i < SPA_PACKET_DATA_SIZE; i++ ) {
		for ( int j = 0; j < spa_char_subs.count; j++ ) {
			if ( p_action_str[i] == spa_char_subs.list[j].before ) {
				p_action_str[i] = spa_char_subs.list[j].after;
				goto __next_subst;   //dont let the loop keep iterating, will cause chain replacements
			}
		}
		__next_subst:
			__asm__ __volatile__("nop");
	}

# ifdef DEBUG
__debuglog(
	printf( "Packet Data hexdump AFTER:\n" );
	print_hex( p_action_str, SPA_PACKET_DATA_SIZE );
)
# endif

	return EXIT_SUCCESS;
}
