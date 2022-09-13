/*
 * Public Key Infrastructure implementation functions and related definitions.
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

#include "pki.h"

#include "../spa.h"
#include "log.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>



// Defining some overloads for this. TODO: Reevaluate the necessity of these.
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

