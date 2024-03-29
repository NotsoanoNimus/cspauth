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


#include "action.h"

#include "conf.h"
#include "log.h"

#include <arpa/inet.h>



// Allocate a pointer array space on the heap to dynamically manage loaded actions.
//   The point of this space is to remove the project dependency on linked lists.
static void* p_actions_base = NULL;
static unsigned long actions_count = 0;



// Create the allocation for the actions to use.
void SPAAction__init() {
    p_actions_base = calloc( 1, (sizeof(spa_action_t*) * SPA_MAX_ACTIONS) );
}

// Return the internal array's length.
unsigned long SPAAction__count() {
    return actions_count;
}

// Deeply clear the heap array.
void SPAAction__clear() {
    if ( NULL == p_actions_base )  return;

    for ( unsigned long x = 0; x < actions_count; x++ )
        free( (void*)(*((spa_action_t**)(p_actions_base + (sizeof(spa_action_t*)*x)))) );

    memset(  p_actions_base, 0, (sizeof(spa_action_t*) * SPA_MAX_ACTIONS)  );
    actions_count = 0;
}


// Get an action from the linked list using the unique action ID.
spa_action_t* SPAAction__get( uint16_t action ) {
    if (  EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_GENERIC_ACTION )  ) {
        __debuglog(
            write_log( "+++ Skipping action ID check: generic_action is set.\n", NULL );
        )
        return &(spa_conf.generic_action);
    } else if ( 0 == actions_count )  return NULL;

    for ( size_t x = 0; x < actions_count; x++ ) {
        spa_action_t* p_item = *((spa_action_t**)(p_actions_base + (sizeof(spa_action_t*)*x)));

        if (  NULL != p_item && action == p_item->action_id  )
            return p_item;
    }

    return NULL;
}



// Create a new action and push it onto the actions list.
spa_action_t* SPAAction__add( uint16_t action, const char* command ) {
    if (  EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_GENERIC_ACTION )  ) {
        write_syslog( LOG_WARNING, "WARNING: Ignoring action with ID %d because"
            " the generic_action option is set.\n", action );
        return NULL;
    } else if ( actions_count >= SPA_MAX_ACTIONS ) {
        write_syslog( LOG_WARNING, "WARNING: The maximum amount of actions has"
            " been loaded. Skipping action '%d'.\n", action );
        return NULL;
    }

    // Finally, create the object in the heap and push it into the linked list.
    spa_action_t* p_action = (spa_action_t*)calloc( 1, sizeof(spa_action_t) );

    p_action->action_id = (uint16_t)(action & 0xFFFF);
    memcpy( &(p_action->command[0]), command, strlen(command) );
    p_action->command[SPA_MAX_ACTION_CMD_LEN-1] = '\0';

    *((spa_action_t**)(p_actions_base + (sizeof(spa_action_t*)*actions_count))) = p_action;
    actions_count++;

    return p_action;
}



// Actually perform the requested action/option combination.
#define SPA_EXP_ACTION_MAX_STRLEN 1024
static inline char* spa_action_get_token_value(
    const char* token_name,
    spa_packet_meta_t* p_packet_meta,
    sa_family_t* listen_family
);
static inline int substitute_packet_data( unsigned char* p_action_str );

int SPAAction__perform(
    spa_action_t* p_action,
    spa_packet_meta_t* p_packet_meta,
    sa_family_t* listen_family
) {
    if ( spa_char_subs.count > 0 ) {
        if (  EXIT_SUCCESS != substitute_packet_data( p_packet_meta->packet.packet_data )  ) {
            __normallog(
                packet_syslog( p_packet_meta->packet_id, LOG_WARNING, "WARNING: There was a"
                    " problem sanitizing the UNSAFE_DATA token expansion.\n", NULL );
            )
            return EXIT_FAILURE;
        }
    }

    char* p_exp_action = (char*)calloc( 1, SPA_EXP_ACTION_MAX_STRLEN );
    memcpy(  p_exp_action, p_action->command,
        strnlen( p_action->command, SPA_MAX_ACTION_CMD_LEN )  );
    p_exp_action[SPA_MAX_ACTION_CMD_LEN] = '\0';   // force null-term


    // =========================================================================
    // Replace the tokens within the action's command with their dynamic values.

    const char* tokens[] = { "[[OPTION]]", "[[ACTION]]", "[[USER]]", "[[SRCIP]]", "[[IPFAM]]",
        "[[SRCPT]]", "[[TIME]]", "[[UNSAFE_DATA]]" };
    char* p_exp_action_tmp = (char*)calloc( 1, SPA_EXP_ACTION_MAX_STRLEN );

    for ( size_t i = 0; i < sizeof(tokens)/sizeof(*tokens); i++ ) {
        __debuglog(
            packet_log( p_packet_meta->packet_id,
                "Expanding action token: '%s'\n", tokens[i] );
        )

        // Each time the loop starts, the updated action string should be copied in.
        memset( p_exp_action_tmp, 0, SPA_EXP_ACTION_MAX_STRLEN );

        // Iterate the updated action string for occurrences of the current token. Found tokens
        //   get inflated into the temp string.
        char* p_save = p_exp_action;
        for ( char* ptr = p_exp_action; *ptr; ptr++ ) {
            // Exit the loop if the strlen plus the token width exceeds the string bounds from the orig cmd.
            int token_len = strnlen( tokens[i], 16 );
            if ( (ptr + token_len) > &p_exp_action[SPA_MAX_ACTION_CMD_LEN-1] )
                break;

            if (  0 == strncmp( ptr, tokens[i], token_len )  ) {
# ifdef DEBUG
__debuglog(
    packet_log( p_packet_meta->packet_id, " `---> Action found token '%s' at pos %d.\n",
        tokens[i], (ptr - p_exp_action) );
)
# endif
                // Append the part of the original string from the save ptr, up to the token.
                strncat( p_exp_action_tmp, p_save, (ptr - p_save) );

                // Get the expanded content and append it.
                char* p_expansion = spa_action_get_token_value(
                    (const char*)tokens[i], p_packet_meta, listen_family );

                if ( NULL == p_expansion ) {
                    free( p_exp_action );
                    free( p_exp_action_tmp );
                    __normallog(
                        packet_syslog( p_packet_meta->packet_id, LOG_WARNING, "WARNING: The expanded action string"
                            " was either invalid (unsafe-data) or the token type was somehow incorrect.\n", NULL );
                    )
                    return EXIT_FAILURE;
                }

                if (
                    (
                        strnlen( p_exp_action_tmp, SPA_EXP_ACTION_MAX_STRLEN+1 )
                            + strnlen( p_expansion, SPA_PACKET_DATA_SIZE+1 )
                    ) > SPA_EXP_ACTION_MAX_STRLEN
                ) {
                    // Bounds exceeded for the string. Don't perform the action.
                    free( p_exp_action );
                    free( p_exp_action_tmp );
                    free( p_expansion );
                    __normallog(
                        packet_syslog( p_packet_meta->packet_id, LOG_WARNING, "WARNING: The expanded action"
                            " string tried to write out-of-bounds. Failing action.\n", NULL );
                    )
                    return EXIT_FAILURE;
                }

                // Otherwise, append.
                strncat ( p_exp_action_tmp, p_expansion, SPA_PACKET_DATA_SIZE );

                // Jump over the token by strlen and set the new save ptr.
                ptr += token_len;
                p_save = ptr;

                free( p_expansion );
            }
        }

        // Finally, push the final part of the string on and len-check it once again.
        if (
            (
                strnlen( p_exp_action_tmp, SPA_EXP_ACTION_MAX_STRLEN+1 )
                    + strnlen( p_save, SPA_EXP_ACTION_MAX_STRLEN+1 )
            ) > SPA_EXP_ACTION_MAX_STRLEN
        ) {
                    // Bounds exceeded for the string. Don't perform the action.
                    free( p_exp_action );
                    free( p_exp_action_tmp );
                    __normallog(
                        packet_syslog( p_packet_meta->packet_id, LOG_WARNING, "WARNING: The expanded action"
                            " string tried to write out-of-bounds. Failing action.\n", NULL );
                    )
                    return EXIT_FAILURE;
        }

        // Otherwise, apppend.
        strncat( p_exp_action_tmp, p_save, SPA_EXP_ACTION_MAX_STRLEN );

        // ... And when the loop finalizes, the updated/expanded string overwrites the original buffer.
        memset( p_exp_action, 0, SPA_EXP_ACTION_MAX_STRLEN );
        memcpy( p_exp_action, p_exp_action_tmp, SPA_EXP_ACTION_MAX_STRLEN );
    }

    // At long last, update the original action string.
    memcpy( p_exp_action, p_exp_action_tmp, SPA_EXP_ACTION_MAX_STRLEN );
    p_exp_action[SPA_EXP_ACTION_MAX_STRLEN - 1] = '\0';   // force null-term

    free( p_exp_action_tmp );


    // =========================================================================
    // =========================================================================


    __debuglog(
        packet_log( p_packet_meta->packet_id,
            "Performing expanded action string: <<<|%s|>>>\n", p_exp_action );
    )

    int rc = system( p_exp_action );
    if (  EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_LOG_EXIT_CODES )  ) {
        packet_syslog(
            p_packet_meta->packet_id,
            ( rc == 0 ) ? LOG_NOTICE : LOG_WARNING,
            "%s: action <<<|%s|>>> returned exit code '%d'.\n",
            (( rc == 0 ) ? "NOTICE" : "WARNING"), p_exp_action, rc
        );
    } else if ( 0 != rc ) {
        __normallog(
            packet_syslog( p_packet_meta->packet_id, LOG_WARNING,
                "WARNING: performed action returned non-zero exit code '%d'.\n", rc );
        )
    }

    free( p_exp_action );
    return (rc != 0) ? EXIT_FAILURE : EXIT_SUCCESS;
}



// Token expansions from packet meta info.
static inline char* spa_action_get_token_value(
    const char* token_name,
    spa_packet_meta_t* p_packet_meta,
    sa_family_t* listen_family
) {
    // The expanded data can be _AT MOST_ the size of the UNSAFE_DATA expansion.
    char* p_expanded_token = (char*)calloc( 1, (SPA_PACKET_DATA_SIZE+1) );

    // Only forced validation is that the string is NOT printing control characters.
    if (  0 == strcmp( token_name, "[[OPTION]]" )  ) {
        sprintf( p_expanded_token, "%d", (p_packet_meta->packet).request_option );

    } else if (  0 == strcmp( token_name, "[[ACTION]]" )  ) {
        sprintf( p_expanded_token, "%d", (p_packet_meta->packet).request_action );

    } else if (  0 == strcmp( token_name, "[[USER]]" )  ) {
        snprintf(
            p_expanded_token, SPA_PACKET_USERNAME_SIZE, "%s",
            (const char*)((p_packet_meta->packet).username)
        );
        p_expanded_token[SPA_PACKET_USERNAME_SIZE] = '\0';

    } else if (  0 == strcmp( token_name, "[[SRCIP]]" )  ) {
        char client_addr[INET6_ADDRSTRLEN];
        memset( &client_addr[0], 0, INET6_ADDRSTRLEN );

        if ( AF_INET == *listen_family ||  (
                (EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_NO_IPV4_MAPPING )) &&
                (IN6_IS_ADDR_V4MAPPED(&(p_packet_meta->clientaddr.sin6_addr)))
        )  ) {
            __debuglog(
                packet_log( p_packet_meta->packet_id,
                    "*** Shrinking clientaddr to IPv4 sockaddr.\n", NULL );
            )

            struct sockaddr_in* p_ip4 =
                (struct sockaddr_in*)calloc( 1, sizeof(struct sockaddr_in) );
            p_ip4->sin_family = AF_INET;
            p_ip4->sin_port = p_packet_meta->clientaddr.sin6_port;
            memcpy( &p_ip4->sin_addr, &((p_packet_meta->clientaddr).sin6_addr.s6_addr[12]), 4 );

            if (  NULL == (inet_ntop( AF_INET, &(p_ip4->sin_addr), client_addr, INET_ADDRSTRLEN ))  ) {
                __debuglog(
                    packet_log( p_packet_meta->packet_id,
                        "***** Unable to get SRCIP (v4) expansion.\n", NULL );
                )
                free( p_expanded_token );
                free( p_ip4 );
                return NULL;
            }

            free( p_ip4 );
        } else {
            __debuglog(
                packet_log( p_packet_meta->packet_id,
                    "*** Using clientaddr as IPv6 sockaddr.\n", NULL );
            )

            if (
                NULL == (inet_ntop( AF_INET6, &((p_packet_meta->clientaddr).sin6_addr),
                    client_addr, INET6_ADDRSTRLEN ))
            ) {
                __debuglog(
                    packet_log( p_packet_meta->packet_id,
                        "***** Unable to get SRCIP (v6) expansion.\n", NULL );
                )
                free( p_expanded_token );
                return NULL;
            }
        }

        snprintf( p_expanded_token, INET6_ADDRSTRLEN+1, "%s", client_addr );
        p_expanded_token[INET6_ADDRSTRLEN] = '\0';

    } else if (  0 == strcmp( token_name, "[[IPFAM]]" )  ) {
        p_expanded_token[0] = ( AF_INET == *listen_family ) ? '4' : '6';
        p_expanded_token[1] = '\0';

    } else if (  0 == strcmp( token_name, "[[SRCPT]]" )  ) {
        sprintf( p_expanded_token, "%d", (p_packet_meta->clientaddr).sin6_port );

    } else if (  0 == strcmp( token_name, "[[TIME]]" )  ) {
        sprintf( p_expanded_token, "%lu", (p_packet_meta->packet).client_timestamp );

    } else if (  0 == strcmp( token_name, "[[UNSAFE_DATA]]" )  ) {
        snprintf( p_expanded_token, SPA_PACKET_DATA_SIZE,
            "%s", (p_packet_meta->packet).packet_data );
        p_expanded_token[SPA_PACKET_DATA_SIZE-1] = '\0';

    } else {
        // u wot m8
        __debuglog(
            packet_log( p_packet_meta->packet_id,
                "Token name '%s' is not valid.\n", token_name );
        )
        free( p_expanded_token );
        return NULL;
    }

    p_expanded_token[SPA_PACKET_DATA_SIZE] = '\0';   // force null-term
    return p_expanded_token;
}



static inline int substitute_packet_data( unsigned char* p_action_str ) {
# ifdef DEBUG
__debuglog(
    printf( "Packet Data hexdump BEFORE:\n" );
    print_hex( (unsigned char*)p_action_str, SPA_PACKET_DATA_SIZE );
)
# endif

    for ( int i = 0; i < SPA_PACKET_DATA_SIZE; i++ ) {
        for ( int j = 0; j < spa_char_subs.count; j++ ) {
            if ( p_action_str[i] == (spa_char_subs.list[j]).before ) {
                p_action_str[i] = (spa_char_subs.list[j]).after;
                goto __next_subst;   //dont let the loop keep iterating, will cause chain replacements
            }
        }
        __next_subst:
            continue;
    }

# ifdef DEBUG
__debuglog(
    printf( "Packet Data hexdump AFTER:\n" );
    print_hex( (unsigned char*)p_action_str, SPA_PACKET_DATA_SIZE );
)
# endif

    return EXIT_SUCCESS;
}
