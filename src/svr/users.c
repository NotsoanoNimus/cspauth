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

#include <err.h>
#include <ctype.h>
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
// Permit this function to kill the application, since it's only ever called on config re/load.
static void get_valid_uint16( uint16_t* result, char* token, char* username, char* type ) {
    if (  strnlen( token, 7 ) > 5  )
        errx( 1, "User '%s' autl policy defines an invalid %s '%s'.\n",
            username, type, token );

    for (  int i = 0; i < strlen( token ); i++  ) {
        if (  !isdigit( (int)(token[i]) )  )
            errx( 1, "User '%s' autl policy defines an invalid %s of '%s'.\n",
                username, type, token );
    }

    uint16_t t = (uint16_t)atoi( token );

    if (  t < 1 || t >= UINT16_MAX  )
        errx( 1, "User '%s' autl policy defines an out-of-range %s of '%d'.\n",
            username, type, t );

    *result = t;
}



// Allocate a pointer array space on the heap to dynamically manage loaded actions.
//   The point of this space is to remove the project dependency on linked lists.
static void* p_users_base = NULL;
static unsigned long users_count = 0;

// Called in the main file to set up the users space allocation.
void SPAUser__init() {
    p_users_base = calloc( 1, (sizeof(spa_user_t*) * SPA_MAX_USERS) );

}

// These are needed as interfaces for "outside" server functionalities.
unsigned long SPAUser__count() {
    return users_count;
}

// Clear the list of allocated users.
void SPAUser__clear() {
    if ( NULL == p_users_base )  return;

    for ( unsigned long x = 0; x < users_count; x++ )
        free(  (void*)(*((spa_user_t**)(p_users_base + (sizeof(spa_user_t*)*x))))  );

    memset( p_users_base, 0, (sizeof(spa_user_t*) * SPA_MAX_USERS) );
    users_count = 0;
}



// Wrapper method to expose the dynamic pointer array allocation.
spa_user_t* SPAUser__get_array() {
    return (spa_user_t*)p_users_base;
}



// Fetch a user from the array.
spa_user_t* SPAUser__get( char* p_username ) {
    strtolower( p_username );
    __debuglog(
        write_log( "*** Getting configuration for user with name: |%s|\n", p_username );
    )

    if (  strlen( p_username ) >= SPA_PACKET_USERNAME_SIZE  ) {
        __debuglog(
            write_log( "~~~~~ The requested username is too long. The limit "
                "is %d characters.\n", SPA_PACKET_USERNAME_SIZE-1 );
        )
        return NULL;
    } else if ( users_count <= 0 ) {
        __debuglog(
            write_log( "~~~~~ No users are loaded; can't fetch user '%s'.\n", p_username );
        )
        return NULL;
    }

    __debuglog(  write_log( "***** Searching '%d' loaded users...\n", users_count );  )
    for ( unsigned long x = 0; x < users_count; x++ ) {
        spa_user_t** pp_user = (spa_user_t**)(p_users_base + (sizeof(spa_user_t*)*x));
        if ( NULL == pp_user )
            continue;

        spa_user_t* p_x = *pp_user;
        if ( NULL == p_x )
            continue;

        __debuglog(  write_log( "******* Checking user '%s'.\n", p_x->username );  )
        if (  0 == strcmp( p_username, p_x->username )  ) {
            if ( ON != p_x->valid_user ) {
                __debuglog(
                    write_log( "~~~~~ The user '%s' was found, but isn't "
                        "marked as a valid user.\n", p_username );
                )
                return NULL;
            }

            __debuglog(
                write_log( "+++++ User '%s' found and valid.\n", p_username );
            )
            return p_x;
        }
    }

    // Represents exec that falls through the loop without finding a user by that name.
    __debuglog(
        write_log( "***** The user was not found in the users array.\n", NULL );
    )
    return NULL;
}



// Add a user to the store of loaded profiles.
spa_user_t* SPAUser__add( char* p_username ) {
    __debuglog(  write_log( "*** Adding user with name '%s'.\n", p_username );  )

    // Check whether that username already exists.
    if (  NULL != SPAUser__get( p_username )  )
        return NULL;

    // Make sure the max user count isn't exceeded. anything more than the limit would really be excessive.
    if ( users_count >= SPA_MAX_USERS ) {
        write_error_log( "Cannot allocate more than %d users.\n", SPA_MAX_USERS );
    }

    // Make sure the username fits the initial parameters.
    if (  strnlen( p_username, SPA_PACKET_USERNAME_SIZE ) >= SPA_PACKET_USERNAME_SIZE  ) {
        write_error_log( "Usernames cannot be greater than "
            "%d characters.\n", SPA_PACKET_USERNAME_SIZE-1 );
    }

    // Check the username against the "regex".
    for ( char* p_x = p_username; *p_x; p_x++ ) {
        if (  !isalnum( (int)*p_x )  ) {
            write_error_log( "Username '%s' is not alphanumeric.\n", p_username );
        }
    }

    // Actually allocate the blank user and copy in the username field.
    spa_user_t* p_user = (spa_user_t*)calloc( 1, sizeof(spa_user_t) );
    memcpy(  &(p_user->username[0]), p_username, strlen( p_username )  );
    p_user->username[SPA_PACKET_USERNAME_SIZE-1] = '\0';   //paranoia

    *((spa_user_t**)(p_users_base + (sizeof(spa_user_t*)*users_count))) = p_user;
    users_count++;

    return p_user;
}



//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////

// Load user authorizations. Since this is called during config parsing and reload,
//   the service is free to throw an error and halt. Thus, the return type is just void.
int SPAUser__load_autls( spa_user_t* p_user_data, char* p_autl_conf_val ) {
    if ( NULL == p_user_data || NULL == p_autl_conf_val )
        return EXIT_FAILURE;

    // Allocate the new authorizations list space as necessary.
    if ( NULL == p_user_data->p_autls ) {
        p_user_data->p_autls = calloc( 1, (sizeof(spa_autl_t) * MAX_USER_AUTH_LISTS) );
    }

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
    while ( NULL != a_token ) {

        int valid_autl = 0;
        spa_autl_t* p_autl = (spa_autl_t*)calloc( 1, sizeof(spa_autl_t) );

        char* b_token_act = strtok_r( a_token, _b_delim, &b );
        char* b_token_opts = strtok_r( NULL, _b_delim, &b );

        if ( NULL != b_token_act && NULL != b_token_opts ) {
            // Both an action and some options are defined.
            uint16_t action_id = 0x0000;
            if (  0 == strcmp( b_token_act, "*" )  ) {
                action_id = 0xFFFF;
                p_autl->any_action = ON;
            } else {
                get_valid_uint16( &action_id, b_token_act, p_user_data->username, "action ID" );
                p_autl->any_action = OFF;
            }
            p_autl->action_id = action_id;

            // Now get the options. A valid AUTL must define at least one option range, even if wildcard.
            if (  0 == strcmp( b_token_opts, "*" )  ) {
                p_autl->opt_range_count = 0x01;
                p_autl->allowed_options[0].low_bound = 0x0000;
                p_autl->allowed_options[0].high_bound = 0xFFFF;

                valid_autl = 1;
                goto eval_autl;
            } else {
                char* c_token = strtok_r( b_token_opts, _c_delim, &c );

                while ( NULL != c_token ) {
                    if ( p_autl->opt_range_count >= SPA_MAX_OPTS_PER_ACTION )
                        errx( 1, "Too many options defined for action '%d' in user '%s'"
                            " autl policy. Limit is %d.\n", action_id, p_user_data->username,
                            SPA_MAX_OPTS_PER_ACTION );

                    spa_option_range_t* p_range = (spa_option_range_t*)calloc( 1, sizeof(spa_option_range_t) );

                    uint16_t range_low;
                    uint16_t range_high;

                    char* d_token_low  = strtok_r( c_token, _d_delim, &d );
                    char* d_token_high = strtok_r( NULL, _d_delim, &d );

                    if ( NULL != d_token_high ) {
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

                    if ( range_high < range_low ) {
                        errx( 1, "The lower boundary of a range cannot be higher than the upper"
                            " bound. low |%d| vs high |%d|.\n", range_low, range_high );
                    }

                    // Code parsing the options should never make it here without crashing, so this should be safe.
                    p_range->low_bound  = range_low;
                    p_range->high_bound = range_high;

                    memcpy( &(p_autl->allowed_options[p_autl->opt_range_count]),
                        p_range, sizeof(spa_option_range_t) );

                    p_autl->opt_range_count++;

                    free( p_range );
                    c_token = strtok_r( NULL, _c_delim, &c );
                }

                if ( p_autl->opt_range_count > 0 )
                    valid_autl = 1;
            }
        }

        eval_autl:
        if ( valid_autl > 0 ) {
            if ( p_user_data->autl_count >= MAX_USER_AUTH_LISTS ) {
                write_error_log( "There was a problem adding an authorization "
                    "list for user '%s'.\n", p_user_data->username );
            }
        }

        // Add the authorization list to the array and increment.
        void* p_dest = (p_user_data->p_autls + (sizeof(spa_autl_t)*p_user_data->autl_count));
        memcpy( p_dest, p_autl, sizeof(spa_autl_t) );
        p_user_data->autl_count++;

        // Free up the object and get the next token.
        free( p_autl );
        a_token = strtok_r( NULL, _a_delim, &a );
    }

    if ( p_user_data->autl_count <= 0 ) {
        fprintf( stderr, "WARNING: User '%s' is not authorized to do anything "
            "according to autl policy.\n", p_user_data->username );
    }

    return EXIT_SUCCESS;
}



// Used mainly for debugging or verbosity in some cases, but dumps information about access a user has.
//   If stream is null, just output through the typical logging methods.
int SPAUser__dump_autls( spa_user_t* p_user_data, FILE* stream ) {
    if ( NULL == p_user_data || 0 == p_user_data->autl_count )
        return EXIT_FAILURE;

    printf( "= DUMPING AUTL FOR USER '%s'.\n", p_user_data->username );
    printf( "= Count of list is %d entries.\n", p_user_data->autl_count );

    spa_autl_t* p_autl = (spa_autl_t*)(p_user_data->p_autls);

    for ( unsigned long x = 0; x < p_user_data->autl_count; x++ ) {
        if ( NULL == p_autl )  break;
        printf( "=== Action ID #%d:\n", p_autl->action_id );

        // Dump information about the available options.
        for ( int i = 0; i < p_autl->opt_range_count; i++ ) {
            uint16_t low  = (p_autl->allowed_options[i]).low_bound;
            uint16_t high = (p_autl->allowed_options[i]).high_bound;
            if ( low == high ) {
                printf( "===== Option #%d\n", low );
            } else {
                printf( "===== Option Range %d - %d\n", low, high );
            }
        }

        // Move to the next auth list.
        p_autl++;
    }

    // Done.
    return EXIT_SUCCESS;
}



// Check a user's autl policies against a list and return whether they're authorized for the action/option.
int SPAUser__is_authorized( spa_user_t* p_user_data, uint16_t action, uint16_t option ) {
    // Users are alwaus authorized to perform an action when the generic action handler is used.
    //   Reminder, this still requires the user to _authenticate_ themselves in the packet signature/timestamp.
    if (  EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_GENERIC_ACTION )  ) {
        return EXIT_SUCCESS;
    }

    if ( NULL == p_user_data || NULL == p_user_data->p_autls )
        return EXIT_FAILURE;
    else if (  p_user_data->autl_count < 1  )
        return EXIT_FAILURE;

    spa_autl_t* p_autl = (spa_autl_t*)(p_user_data->p_autls);

    for ( unsigned long x = 0; x < p_user_data->autl_count; x++ ) {
        // If this autl doesn't permit "*" (any) and the action ID isn't a match, move on.
        if ( ON != p_autl->any_action && action != p_autl->action_id )
            continue;

        // Otherwise, check the options ranges. low <= x <= high
        for ( int j = 0; j < p_autl->opt_range_count; j++ ) {
            uint16_t low  = (p_autl->allowed_options[j]).low_bound;
            uint16_t high = (p_autl->allowed_options[j]).high_bound;
            if (  option >= low && option <= high  ) {
                return EXIT_SUCCESS;
            }
        }

        // Move to the next user auth list.
        p_autl++;
    }

    // Return failure by default if all action-option policies were checked and there's not a match.
    return EXIT_FAILURE;
}



//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////
// User PKEY-related functions.

// Both of the header-file functions wrap this single method, with two different behaviors.
static int _load_user_pkey( struct spa_user_data_t* p_user_data, char* p_pem_filename, int is_save );


// Fetch pkey information while also loading it into the user structure and into memory.
int SPAUser__load_pkey( spa_user_t* p_user_data, char* p_pem_filename ) {
    return _load_user_pkey( p_user_data, p_pem_filename, ON );
}


// Fetch pkey information from the user profile, without saving or modifying any data.
int SPAUser__get_pkey( spa_user_t* p_user_data ) {
    char* p_tmppath = strndup( &(p_user_data->pkey_path[0]), PATH_MAX );

    int rc =  _load_user_pkey( p_user_data, p_tmppath, OFF );

    free( p_tmppath );
    return rc;
}



// NOTE: This call REQUIRES the p_user_data item to be saved because it loads and discards heap data.
static int _load_user_pkey( spa_user_t* p_user_data, char* p_pem_filename, int is_save ) {
    if (  strnlen( p_pem_filename, 4 ) <= 0  ) {
        __debuglog(
            printf( "*** No PEM filename was given.\n" );
        )
        return EXIT_FAILURE;
    }

    X509* cert = NULL;
    EVP_PKEY* pkey = NULL;

    BIO* certbio = BIO_new( BIO_s_file() );
    BIO* outbio  = BIO_new_fp( stdout, BIO_NOCLOSE );

    int exit_code = EXIT_FAILURE;
    __debuglog(
        printf( "*** Reading public key '%s' for user '%s'.\n",
            p_pem_filename, p_user_data->username );
    )

    BIO_read_filename( certbio, p_pem_filename );

    if (  NULL != (cert = PEM_read_bio_X509( certbio, NULL, 0, NULL ))  ) {
        __debuglog(  printf( "***** Read x509; attempting to extract pubkey.\n" );  )

        if (  NULL == (pkey = X509_get_pubkey(cert))  ) {
            BIO_printf( outbio, "~~~ Problem getting public key from "
                "x509 certificate '%s'.\n", p_pem_filename );
            goto end;
        }
    } else {
        __debuglog(
            printf( "***** Failed to load as an x509, trying raw pubkey.\n" );
        )

        BIO* pubkeybio = BIO_new( BIO_s_file() );
        BIO_read_filename( pubkeybio, p_pem_filename );

        pkey = PEM_read_bio_PUBKEY( pubkeybio, NULL, NULL, NULL );

        BIO_free_all( pubkeybio );

        if ( NULL == pkey ) {
            BIO_printf( outbio, "~~~ Problem loading PEM x509 certificate or raw"
                " public key '%s' into memory.\n", p_pem_filename );
            goto end;
        }
    }

    __debuglog(
        printf( "*** Got PEM public key:\n" );
        PEM_write_bio_PUBKEY( outbio, pkey );
    )

    __debuglog(
        printf(  "*** Public key size is %d bits.\n", EVP_PKEY_bits( pkey )  );
    )

    if (  EVP_PKEY_size( pkey ) > SPA_PACKET_MAX_SIGNATURE_SIZE  ) {
        fprintf( stderr, "ERROR: The public key expected signature size exceeds"
            " the maximum size of %d bytes.\n", SPA_PACKET_MAX_SIGNATURE_SIZE );
        goto end;
    }

    if ( ON == is_save ) {
        if ( NULL != p_user_data->pkey ) {
            // Free the old key if one is assigned.
            EVP_PKEY_free( p_user_data->pkey );
        }
        p_user_data->pkey = pkey;

        memset( &(p_user_data->pkey_path[0]), 0, PATH_MAX );
        memcpy( &(p_user_data->pkey_path[0]), p_pem_filename, strnlen( p_pem_filename,PATH_MAX-1 ) );
    } else {
        if ( NULL != pkey )
            EVP_PKEY_free( pkey );
    }

    exit_code = EXIT_SUCCESS;

    end:
        if ( NULL != pkey && EXIT_SUCCESS != exit_code )
            EVP_PKEY_free( pkey );

        if ( NULL != cert )
            X509_free( cert );

        BIO_free_all( certbio );
        BIO_free_all( outbio );

        return exit_code;
}
