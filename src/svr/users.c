/*
 * Definitions and implementations related to user management.
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


#include "users.h"

#include "log.h"
#include "conf.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>



// Quick internal to-lower function.
static inline void strtolower( char* str ) {
    for ( char* x = str; *x; ++x )
        *x = tolower( *x );
}



// Uses a static users list that gets manually cleared every time the service receives restart signals.
LIST* users_list = NULL;

// These are needed as interfaces for "outside" server functionalities.
LIST_NODE* get_user_head() {
    return list_get_head_node( users_list );
}
uint32_t get_user_count() {
    return list_get_count( users_list );
}



// "LOCAL" FUNCTIONS. //
// Permit this function to kill the application, since it's only ever called on config re/load.
void get_valid_uint16( uint16_t* result, char* token, BYTE* username, char* type ) {
    if ( strnlen(token,7) > 5 )
        errx( 1, "User '%s' autl policy defines an invalid %s '%s'.\n", username, type, token );

    for ( int i = 0; i < strlen(token); i++ ) {
        if ( !isdigit(token[i]) )
            errx( 1, "User '%s' autl policy defines an invalid %s of '%s'.\n", username, type, token );
    }

    uint16_t t = (uint16_t)atoi( token );

    if ( t < 1 || t >= UINT16_MAX )
        errx( 1, "User '%s' autl policy defines an out-of-range %s of '%d'.\n", username, type, t );

    *result = t;
}
//////////////////////



USER* get_user( BYTE* username ) {
    strtolower( (char*)username );

    for ( LIST_NODE* node = list_get_head_node( users_list ); node != NULL; node = node->next ) {
        if ( strcmp( (const char*)username, (const char*)(((USER*)(node->node))->username) ) == 0 ) {
            return ((USER*)(node->node));
        }
    }
    return NULL;
}



USER* create_user( BYTE* username ) {
    strtolower( (char*)username );

    // Check whether that username already exists.
    if ( get_user( username ) != NULL )  return NULL;

    // Make sure the max user count isn't exceeded. anything more than the limit would really be excessive.
    if ( list_get_count( users_list ) >= MAX_USERS ) {
        write_error_log( "Cannot allocate more than %d users.\n", MAX_USERS );
    }

    // Make sure the username fits the initial parameters.
    if ( strnlen( (const char*)username, SPA_PACKET_USERNAME_SIZE ) >= SPA_PACKET_USERNAME_SIZE ) {
        write_error_log( "Usernames cannot be greater than %d characters.\n", SPA_PACKET_USERNAME_SIZE-1 );
    }

    // Check the username against the "regex".
    for ( int i = 0; i < strnlen( (const char*)username, SPA_PACKET_USERNAME_SIZE ); i++ ) {
        if ( !isalnum( username[i] ) ) {
            write_error_log( "Username '%s' is not alphanumeric.\n", username );
        }
    }

    // Actually allocate the blank user and copy in the username field.
    //   Also, generate the autl list initializer.
    malloc_sizeof( USER, p_user );

    memcpy( &p_user->username[0], username, strnlen((const char*)username,SPA_PACKET_USERNAME_SIZE) );
    p_user->username[SPA_PACKET_USERNAME_SIZE-1] = '\0';   //paranoia

    p_user->autl = new_list( sizeof(AUTL)*MAX_USER_AUTH_LISTS );

    list_add_node( users_list, p_user );
    return p_user;
}

void clear_all_users() {
    LIST_NODE* x = list_get_head_node( users_list );
    while ( x != NULL ) {
        if ( x->node != NULL && ((USER*)(x->node))->autl != NULL ) {
            destroy_list( ((USER*)(x->node))->autl );
        }
        x = x->next;
    }

    destroy_list( users_list );
    users_list = new_list( MAX_USERS );
}



USER* get_config_for_user( BYTE* username ) {
    __debuglog( write_log( "*** Getting configuration for user with name: |%s|\n", username ); )

    if ( strnlen( (const char*)username, SPA_PACKET_USERNAME_SIZE ) >= SPA_PACKET_USERNAME_SIZE ) {
        __debuglog( write_log( "~~~~~ The requested username is too long. The limit is %d characters.\n", SPA_PACKET_USERNAME_SIZE-1 ); )
        return NULL;
    } else if ( get_user_count() <= 0 ) {
        __debuglog( write_log( "~~~~~ No users are loaded; can't fetch user '%s'.\n", username ); )
        return NULL;
    }

    USER* x = get_user( username );
    if ( x == NULL ) {
        __debuglog( write_log( "~~~~~ No user named '%s' could be found in the loaded linked list.\n", username ); )
        return NULL;
    }

    if ( x->valid_user != ON ) {
        __debuglog( write_log( "~~~~~ The user '%s' was found, but isn't marked as a valid user.\n", username ); )
        return NULL;
    }

    __debuglog( write_log( "+++++ User '%s' found and valid.\n", username ); )
    malloc_sizeof( USER, p_user_data );
    memcpy( p_user_data, x, sizeof(USER) );
    return p_user_data;
}



int set_config_for_user( USER* p_user_data ) {
    __debuglog( write_log( "*** Setting configuration for user with name: |%s|\n", p_user_data->username ); )

    p_user_data->username[SPA_PACKET_USERNAME_SIZE-1] = '\0';   //  P A R A N O I A

    if ( list_get_count( users_list ) <= 0 ) {
        __debuglog( write_log( "~~~~~ No users are loaded.\n", NULL ); )
        return EXIT_FAILURE;
    }

    USER* x = get_user( p_user_data->username );
    if ( x == NULL ) {
        __debuglog( write_log( "~~~~~ No user named '%s' is defined.\n", p_user_data->username ); )
        return EXIT_FAILURE;
    }

    __debuglog( write_log( "+++++ Saving user configuration for found user '%s'.\n", p_user_data->username ); )
    memset( x, 0, sizeof(USER) );
    memcpy( x, p_user_data, sizeof(USER) );
    return EXIT_SUCCESS;
}







//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

// Load user authorizations. Since this is called during config parsing and reload,
//   the service is free to throw an error and halt. Thus, the return type is just void.
int load_user_autls( struct spa_user_data_t* p_user_data, char* p_autl_conf_val ) {
    // A sample authorization list looks like:
    //   autl:zpuhl = 22,0-400+5445+999|8445,0|8446,*
    //    where each pipe-separated section is an action/options authorization, comma
    //    separates actions from opts, and + separates options.
    char _a_delim[2] = { '|', '\0' }; // a = action,options|action,options|...|action,options
    char _b_delim[2] = { ',', '\0' }; // b = action,options
    char _c_delim[2] = { '+', '\0' }; // c = option+optrange+option+...+option
    char _d_delim[2] = { '-', '\0' }; // d = optrangelow-optrangehigh

    // It is assumed that p_autl_conf_val is verified and validated BEFORE being sent to this function.
    //   It's also assumed that the user data passed in is loaded and does NOT already have AUTL policies defined.

    // the naming got too complex for these. just imagine the scope from highest to lowest
    char* a = NULL;
    char* b = NULL;
    char* c = NULL;
    char* d = NULL;

    // Holds all ACTION_ID,OPT_RANGES combinations from the initial string split.
    char* a_token = strtok_r( p_autl_conf_val, _a_delim, &a );
    while ( a_token != NULL ) {

        int valid_autl = 0;
        malloc_sizeof( AUTL, autl );

        char* b_token_act = strtok_r( a_token, _b_delim, &b );
        char* b_token_opts = strtok_r( NULL, _b_delim, &b );
        if ( b_token_act != NULL && b_token_opts != NULL ) {
            // Both an action and some options are defined.
            uint16_t action_id = 0x0000;
            if ( strcmp( b_token_act, "*" ) == 0 ) {
                action_id = 0xFFFF;
                autl->any_action = ON;
            } else {
                get_valid_uint16( &action_id, b_token_act, p_user_data->username, "action ID" );
                autl->any_action = OFF;
            }
            autl->action_id = action_id;

            // Now get the options. A valid AUTL must define at least one option range, even if wildcard.
            if ( strcmp( b_token_opts, "*" ) == 0 ) {
                autl->opt_range_count = 0x01;
                autl->allowed_options[0].low_bound = 0x0000;
                autl->allowed_options[0].high_bound = 0xFFFF;
                valid_autl = 1;
                goto eval_autl;
            } else {
                char* c_token = strtok_r( b_token_opts, _c_delim, &c );
                while ( c_token != NULL ) {
                    if ( autl->opt_range_count >= SPA_MAX_OPTS_PER_ACTION )
                        errx( 1, "Too many options defined for action '%d' in user '%s'"
                            " autl policy. Limit is %d.\n", action_id, p_user_data->username,
                            SPA_MAX_OPTS_PER_ACTION );

                    malloc_sizeof( struct spa_user_autl_opt_range_t, opt_range );

                    uint16_t range_low;
                    uint16_t range_high;

                    char* d_token_low  = strtok_r( c_token, _d_delim, &d );
                    char* d_token_high = strtok_r( NULL, _d_delim, &d );
                    if ( d_token_high != NULL ) {
                        // it's a range.
                        get_valid_uint16( &range_low, d_token_low, p_user_data->username, "low option value" );
                        get_valid_uint16( &range_high, d_token_high, p_user_data->username, "high option value" );
                    } else {
                        // it's a single option number.
                        uint16_t option_val = 1;
                        get_valid_uint16( &option_val, c_token, p_user_data->username, "option value" );
                        range_low  = option_val;
                        range_high = option_val;
                    }

                    if ( range_high < range_low )
                        errx( 1, "The lower boundary of a range cannot be higher than the upper"
                            " bound. low |%d| vs high |%d|.\n", range_low, range_high );

                    // Code parsing the options should never make it here without crashing, so this should be safe.
                    opt_range->low_bound  = range_low;
                    opt_range->high_bound = range_high;

                    memcpy( &autl->allowed_options[autl->opt_range_count],
                        opt_range, sizeof(struct spa_user_autl_opt_range_t) );

                    autl->opt_range_count++;

                    free( opt_range );
                    c_token = strtok_r( NULL, _c_delim, &c );
                }

                if ( autl->opt_range_count > 0 )  valid_autl = 1;
            }
        }

        eval_autl:
        if ( valid_autl > 0 ) {
            if ( list_add_node( p_user_data->autl, autl ) != EXIT_SUCCESS ) {
                write_error_log( "There was a problem adding an authorization list for user '%s'.\n", p_user_data->username );
            }
        }
        // Free up the object and get the next token.
        a_token = strtok_r( NULL, _a_delim, &a );
    }

    if ( list_get_count( p_user_data->autl ) <= 0 ) {
        fprintf( stderr, "WARNING: User '%s' is not authorized to do anything "
            "according to autl policy.\n", p_user_data->username );
    } else {
        set_config_for_user( p_user_data );
    }

    return EXIT_SUCCESS;
}



// Used mainly for debugging or verbosity in some cases, but dumps information about access a user has.
//   If stream is null, just output through the typical logging methods.
int dump_user_autls( struct spa_user_data_t* p_user_data, FILE* stream ) {
    printf( "= DUMPING AUTL FOR USER '%s'.\n", p_user_data->username );
    printf( "= Count of list is %d entries.\n", list_get_count( p_user_data->autl ) );

    LIST_NODE* current = list_get_head_node( p_user_data->autl );
    while ( current != NULL ) {
        struct spa_user_autl_t* p_autl = (AUTL*)current->node;
        printf( "=== Action ID #%d:\n", p_autl->action_id );

        for ( int i = 0; i < p_autl->opt_range_count; i++ ) {
            uint16_t low  = p_autl->allowed_options[i].low_bound;
            uint16_t high = p_autl->allowed_options[i].high_bound;
            if ( low == high ) {
                printf( "===== Option #%d\n", low );
            } else {
                printf( "===== Option Range %d - %d\n", low, high );
            }
        }

        current = current->next;
    }

    return EXIT_SUCCESS;
}



// Check a user's autl policies against a list and return whether they're authorized for the action/option.
int is_user_authorized( struct spa_user_data_t* p_user_data, uint16_t* action_id, uint16_t* option ) {
    // Users are alwaus authorized to perform an action when the generic action handler is used.
    //   Reminder, this still requires the user to _authenticate_ themselves in the packet signature/timestamp.
    if ( get_config_flag( SPA_CONF_FLAG_GENERIC_ACTION ) == EXIT_SUCCESS )
        return EXIT_SUCCESS;

    uint32_t autl_count = list_get_count( p_user_data->autl );
    if ( autl_count < 1 || autl_count > MAX_USER_AUTH_LISTS )  return EXIT_FAILURE;

    for ( LIST_NODE* p_node = list_get_head_node( p_user_data->autl ); p_node != NULL; p_node = p_node->next ) {
        AUTL* p_autl = ((AUTL*)p_node->node);

        // If this autl doesn't permit "*" (any) and the action ID isn't a match, move on.
        if ( p_autl->any_action != ON && p_autl->action_id != *action_id )  continue;

        // Otherwise, check the options ranges. low <= x <= high
        for ( int j = 0; j < p_autl->opt_range_count; j++ ) {
            uint16_t low  = p_autl->allowed_options[j].low_bound;
            uint16_t high = p_autl->allowed_options[j].high_bound;
            if ( *option >= low && *option <= high ) {
                return EXIT_SUCCESS;
            }
        }
    }

    // Return failure by default if all action-option policies were checked and there's not a match.
    return EXIT_FAILURE;
}



//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
// User PKEY-related functions.

int __load_user_pkey( struct spa_user_data_t* p_user_data, BYTE* p_pem_filename, int is_save );
int load_user_pkey( struct spa_user_data_t* p_user_data, BYTE* p_pem_filename ) {
    return __load_user_pkey( p_user_data, p_pem_filename, ON );
}
int get_user_pkey( struct spa_user_data_t* p_user_data ) {
    BYTE* p_tmppath = (BYTE*)strndup( (const char*)&(p_user_data->pkey.key_path[0]), PATH_MAX );
    return __load_user_pkey( p_user_data, p_tmppath, OFF );
}



// NOTE: This call REQUIRES the p_user_data item to be saved because it loads and discards heap data.
int __load_user_pkey( struct spa_user_data_t* p_user_data, BYTE* p_pem_filename, int is_save ) {
    if ( strnlen( (const char*)p_pem_filename, 4 ) <= 0 ) {
        __debuglog( printf( "*** No PEM filename was given.\n" ); )
        return EXIT_FAILURE;
    }

    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;

    BIO* certbio = BIO_new( BIO_s_file() );
    BIO* outbio  = BIO_new_fp( stdout, BIO_NOCLOSE );

    int exit_code = EXIT_FAILURE;
    __debuglog( printf( "*** Reading public key '%s' for user '%s'.\n",
        p_pem_filename, p_user_data->username ); )

    BIO_read_filename( certbio, (const char*)p_pem_filename );
    if ( (cert = PEM_read_bio_X509( certbio, NULL, 0, NULL )) != NULL ) {
        __debuglog( printf( "***** Read x509; attempting to extract pubkey.\n" ); )
        if ( (pkey = X509_get_pubkey(cert)) == NULL ) {
            BIO_printf( outbio, "ERROR getting public key from x509 certificate '%s'.\n", p_pem_filename );
            goto end;
        }
    } else {
        __debuglog( printf( "***** Failed to load as an x509, trying raw pubkey.\n" ); )

        BIO* pubkeybio = BIO_new( BIO_s_file() );
        BIO_read_filename( pubkeybio, (const char*)p_pem_filename );
        pkey = PEM_read_bio_PUBKEY( pubkeybio, NULL, NULL, NULL );
        BIO_free_all( pubkeybio );

        if ( pkey == NULL ) {
            BIO_printf( outbio, "ERROR loading PEM x509 certificate or raw"
                " public key '%s' into memory.\n", p_pem_filename );
            goto end;
        }
    }

    __debuglog(
        printf( "*** Got PEM public key:\n" );
        PEM_write_bio_PUBKEY( outbio, pkey );
    )

    __debuglog( printf( "*** Public key size is %d bits.\n", EVP_PKEY_bits( pkey ) ); )

    if ( EVP_PKEY_size( pkey ) > SPA_PACKET_MAX_SIGNATURE_SIZE ) {
        fprintf( stderr, "ERROR: The public key expected signature size exceeds"
            " the maximum size of %d bytes.\n", SPA_PACKET_MAX_SIGNATURE_SIZE );
        goto end;
    }

    if ( is_save == ON ) {
        if ( p_user_data->pkey.evp_pkey != NULL ) {
            // Free the old key if one is assigned.
            EVP_PKEY_free( p_user_data->pkey.evp_pkey );
        }
        p_user_data->pkey.evp_pkey = pkey;

        memset( &p_user_data->pkey.key_path[0], 0, PATH_MAX );
        memcpy( &p_user_data->pkey.key_path[0], (const char*)p_pem_filename,
            strnlen( (const char*)p_pem_filename,PATH_MAX-1 ) );

        set_config_for_user( p_user_data );
    } else {
        if ( pkey != NULL )  EVP_PKEY_free( pkey );
    }

    exit_code = EXIT_SUCCESS;
    end:
        if ( pkey != NULL && exit_code != EXIT_SUCCESS )  EVP_PKEY_free( pkey );
        if ( cert != NULL )  X509_free( cert );
        BIO_free_all( certbio );
        BIO_free_all( outbio );
        return exit_code;
}
