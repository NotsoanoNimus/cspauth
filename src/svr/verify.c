/*
 * Functions and implementations related to the processing and verification
 *  of inbound SPA packets to the server daemon.
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


#include "verify.h"

#include "log.h"
#include "conf.h"
#include "../integrity.h"

#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>



// Packet pre-filtering. Anything rejected at this stage will NEVER emit a response packet, regardless of mode.
int pre_packet_verify( unsigned char* p_input_buffer ) {
    int exit_code = EXIT_FAILURE;
    __debuglog(  printf( "*** Packet pre-checks.\n" );  )

    spa_packet_t* p_packet = (spa_packet_t*)calloc( 1, sizeof(spa_packet_t) );
    memcpy( p_packet, p_input_buffer, sizeof(spa_packet_t) );

    if ( p_packet->signature_length <= 0 ) {
        __debuglog(  printf( "***** Packet signature below minimum length.\n" );  )
        goto __err;
    } else if ( p_packet->signature_length > SPA_PACKET_MAX_SIGNATURE_SIZE ) {
        __debuglog(  printf( "***** Packet signature exceeds maximum length.\n" );  )
        goto __err;
    }

    if (  0x00 == p_packet->request_action  ) {
        __debuglog(  printf( "***** Packet signature below minimum length.\n" );  )
        goto __err;
    } else if (  0x00 == p_packet->request_option  ) {
        __debuglog(  printf( "***** Packet signature below minimum length.\n" );  )
        goto __err;
    }

    if (  strnlen( (const char*)(p_packet->username), 3 ) <= 0  ) {
        __debuglog(  printf( "***** Packet doesn't have a username.\n" );  )
        goto __err;
    }

    __debuglog(  printf( "***** Packet pre-check is OK.\n" );  )
    exit_code = EXIT_SUCCESS;

    __err:
        free( p_packet );
        return exit_code;
}



// Get the current epoch time according to the server/daemon, and calculate the window of acceptable timestamps.
int verify_timestamp( uint64_t packet_id, uint64_t timestamp ) {
    __verboselog(
        packet_log( packet_id, "+++ Checking packet timestamp '%lu'.\n", timestamp );
    )

    time_t now;
    time( &now );
    uint64_t epochTime = (uint64_t)now;
    uint64_t minRange = (epochTime - spa_conf.validity_window);
    uint64_t maxRange = (epochTime + spa_conf.validity_window);

    __debuglog(
        packet_log( packet_id, "+++ Server epoch time is: |%lu|. Acceptable packet "
            "boundaries are: |%lu| <---> |%lu|\n", now, minRange, maxRange );
    )

    if (  timestamp < minRange || timestamp > maxRange  ) {
        __verboselog(
            packet_log( packet_id, "~~~~~ The client timestamp did not fall within the "
                "acceptable window.\n", NULL );
        )
        return EXIT_FAILURE;
    } else {
        __verboselog(
            packet_log( packet_id, "+++++ The timestamp is OK.\n", NULL );
        )
        return EXIT_SUCCESS;
    }
}



// Verifies that the username is valid and loaded. Really just a wrapper function.
int verify_username( uint64_t packet_id, unsigned char* p_username ) {
    __verboselog(
        packet_log( packet_id, "+++ Attempting to get user configuration for '%s'.\n", p_username );
    )
    int exit_code = EXIT_FAILURE;

    // Temporarily switch on debug logging when the log level is verbose or higher.
    //   This is to see what's happening in detail within the SPAUser__get function as needed.
    uint8_t old_level = spa_conf.log_level;
    if ( spa_conf.log_level >= verbose )
        spa_conf.log_level = debug;

    spa_user_t* p_user = SPAUser__get( p_username );

    if ( NULL == p_user ) {
        spa_conf.log_level = old_level;
        __verboselog(
            packet_log( packet_id, "~~~~~ User configuration is missing or otherwise invalid.\n", NULL );
        );
        goto __exit;
    }


    __verboselog(
        packet_log( packet_id, "+++++ Username is OK.\n", NULL );
    )
    exit_code = EXIT_SUCCESS;

    __exit:
        spa_conf.log_level = old_level;
        return exit_code;
}



// Hash the packet (using hash_packet from the integrity implementation),
//   and verify the provided hash matches the calculated one.
int verify_packet_hash( uint64_t packet_id, spa_packet_t* p_spa_packet ) {
    __verboselog(
        packet_log( packet_id, "+++ Generating sha256 packet hash...\n", NULL );
    )

    unsigned char digest[SHA256_DIGEST_LENGTH];
    if (  (hash_packet( digest, p_spa_packet )) < 1  ) {
        __verboselog(
            packet_log( packet_id, "~~~~~ Failed to generate a hash for the packet.\n", NULL );
        )
        return EXIT_FAILURE;
    }

# ifdef DEBUG
    __debuglog(
        fprintf( stderr, "Hashed SPA packet and got hexdump result:\n" );
        print_hex( digest, SHA256_DIGEST_LENGTH );
    )
# endif

    for ( int x = 0; x < SHA256_DIGEST_LENGTH; x++ ) {
        if ( digest[x] != p_spa_packet->packet_hash[x] ) {
            __verboselog(
                packet_log( packet_id,  "~~~~~ Packet sha256 hash mismatch.\n", NULL );
            )
            return EXIT_FAILURE;
        }
    }

    __verboselog(
        packet_log( packet_id, "+++++ sha256 hash is OK.\n", NULL );
    )
    return EXIT_SUCCESS;
}



// Verify that the provided action ID is loaded in the running configuration.
int verify_action( uint64_t packet_id, spa_action_t* p_spa_action, uint16_t action ) {
    __verboselog(
        packet_log( packet_id, "+++ Attempting to get action for ID '%d'.\n", action );
    )

    // Temporarily switch on debug logging when the log level is verbose or higher.
    //   This is to see what's happening in detail within the get_action_by_id function.
    uint8_t old_level = spa_conf.log_level;
    if ( spa_conf.log_level >= verbose )
        spa_conf.log_level = debug;

    spa_action_t* p_action_s = SPAAction__get( action );
    if ( NULL == p_action_s ) {
        spa_conf.log_level = old_level;
        __verboselog(
            packet_log( packet_id, "~~~~~ Action ID is not loaded or is otherwise missing.\n", NULL );
        )
        return EXIT_FAILURE;
    }

    memcpy( p_spa_action, p_action_s, sizeof(spa_action_t) );
    spa_conf.log_level = old_level;

    __verboselog(
        packet_log( packet_id, "+++++ Action ID is OK.\n", NULL );
    )
    return EXIT_SUCCESS;
}



// Check if the user's loaded authorization list contains an action/option combination encompassing
//   the provided range from the SPA packet.
int verify_authorization(
    uint64_t packet_id,
    spa_user_t* p_user_data,
    uint16_t action,
    uint16_t option
) {
    if (  EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_GENERIC_ACTION )  ) {
        __verboselog(
            packet_log( packet_id, "+++ Skipping authorization check: generic_action is set.\n", NULL );
        )
        return EXIT_SUCCESS;
    }

    __verboselog(
        packet_log( packet_id, "+++ Checking authorization of user '%s' for"
            " action ID '%d' with option '%d'.\n", p_user_data->username, action, option );
    )

    __debuglog(
        SPAUser__dump_autls( p_user_data, stdout );
    )

    if (  p_user_data->autl_count < 1 || p_user_data->autl_count > MAX_USER_AUTH_LISTS  ) {
        __verboselog(
            packet_log( packet_id, "~~~~~ User has no, or too many (%d),"
                " authorization entries: %d\n", MAX_USER_AUTH_LISTS, p_user_data->autl_count );
        )
        return EXIT_FAILURE;
    }

    if (  EXIT_SUCCESS == SPAUser__is_authorized( p_user_data, action, option )  ) {
        __verboselog(
            packet_log( packet_id, "+++++ Authorization is OK.\n", NULL );
        )
        return EXIT_SUCCESS;
    }

    // Return failure by default if all action-option policies were checked and there's not a match.
    __verboselog(
        packet_log( packet_id, "~~~~~ User '%s' is not authorized to perform "
            "this function.\n", p_user_data->username );
    )
    return EXIT_FAILURE;
}



int verify_pubkey( uint64_t packet_id, spa_user_t* p_user_data ) {
    __verboselog(
        packet_log( packet_id, "+++ Attempting to get/check public key "
            "for user '%s'.\n", p_user_data->username );
    )

    // Temporarily switch on debug logging when the log level is verbose or higher.
    //   This is to see what's happening in detail within the get function.
    uint8_t old_level = spa_conf.log_level;
    if ( spa_conf.log_level >= verbose )
        spa_conf.log_level = debug;

    // Reloads the user's pubkey with every packet, in case the file on the disk has changed to a new key.
    if (  EXIT_SUCCESS != SPAUser__get_pkey( p_user_data )  ) {
        spa_conf.log_level = old_level;
        __verboselog(
            packet_log( packet_id, "~~~~~ User public key could not be loaded or is "
                "otherwise invalid.\n", NULL );
        )
        return EXIT_FAILURE;
    }

    spa_conf.log_level = old_level;

    __verboselog(
        packet_log( packet_id, "+++++ Public Key is OK.\n", NULL );
    )
    return EXIT_SUCCESS;
}



// Verify the actual crypto signature attached to the packet.
int verify_signature(
    uint64_t packet_id,
    spa_packet_t* p_spa_packet,
    spa_user_t* p_user_data
) {
    __verboselog(
        packet_log( packet_id, "+++ Checking packet's SHA256 signature with the user's pubkey.\n", NULL );
    )

    EVP_MD_CTX* mdctx = NULL;
    EVP_MD_CTX* dummymdctx = NULL;
    int rc = -255;

    __debuglog(  printf( "***** Ensuring a user pubkey exists.\n" );  )
    if (  NULL == p_user_data->pkey  )
        goto __err;

    int keysize = EVP_PKEY_size( p_user_data->pkey );
    __debuglog(
        printf( "******* Got user pubkey size of '%d' bits, signature approx '%d' bytes.\n",
            EVP_PKEY_bits( p_user_data->pkey ), keysize );
    )
    if ( keysize <= 0 )
        goto __err;

    __debuglog(  printf( "***** Getting actual signature size.\n" );  )
    uint32_t siglen = p_spa_packet->signature_length;
    if (  siglen <= 0 || siglen > SPA_PACKET_MAX_SIGNATURE_SIZE  )
        goto __err;
    __debuglog(  printf( "******* Got packet signature length '%u'.\n", siglen );  )

    __debuglog(  printf( "***** Creating message digest context.\n" );  )
    if (  !(mdctx = EVP_MD_CTX_create())  )
        goto __err;

    __debuglog(  printf( "***** Initializing message digest context.\n" );  )
    if (  1 != EVP_DigestVerifyInit( mdctx, NULL, EVP_sha256(), NULL, p_user_data->pkey )  )
        goto __err;

    __debuglog(  printf( "***** Updating message digest context.\n" );  )
    if (  1 != EVP_DigestVerifyUpdate( mdctx, p_spa_packet->packet_hash, SHA256_DIGEST_LENGTH )  )
        goto __err;

    __debuglog(  printf( "***** Verifying signature...\n" );  )
    rc = EVP_DigestVerifyFinal( mdctx, p_spa_packet->packet_signature, siglen );


    __err:
    if ( 1 != rc ) {
        __verboselog(
            packet_log( packet_id, "~~~~~ Signature verification failed: %d. Attempting "
                "to get why...\n", rc );
        )

        while ( 0 != ERR_peek_error() ) {
            char* openssl_err_sub = (char*)calloc( 1, 256 );

            unsigned long opensslerrno = ERR_get_error();
            ERR_error_string_n( opensslerrno, openssl_err_sub, 256 );

            __verboselog(
                packet_log( packet_id,  "~~~~~  ---> OpenSSL error %lu: %s\n", opensslerrno, openssl_err_sub );
            )

            free( openssl_err_sub );
        }
    }

    if ( mdctx )
        EVP_MD_CTX_destroy( mdctx );

    if ( dummymdctx )
        EVP_MD_CTX_destroy( dummymdctx );

    if ( 1 == rc ) {
        __verboselog(
            packet_log( packet_id, "+++++ Packet signature is OK.\n", NULL );
        )
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}
