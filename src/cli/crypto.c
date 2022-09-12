/*
 * Crypto-related client functions. Implements from the shared "integrity"
 *  header file.
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


#include "../integrity.h"



#define __debug( ... ) \
    if ( *is_debug == ON ) { __VA_ARGS__ }



// Verify the actual crypto signature attached to the packet.
int sign_packet( BYTE* key_file, spa_packet_t* p_packet, int* is_debug ) {
    __debug( printf( "crypto: Checking packet's SHA256 signature with the user's pubkey.\n" ); )

    int rc = -1;
    FILE* fp = NULL;
    EVP_PKEY* pkey = NULL;

    EVP_MD_CTX* mdctx = NULL;
    BYTE* sig = NULL;

    size_t slen = 0;


    __debug( printf( "crypto: Attempting to load PEM private key file '%s'.\n", key_file ); )
    if ( (fp = fopen((const char*)key_file,"r")) == NULL ) {
        fprintf( stderr, "crypto: Failed to load private key file.\n" );
        goto __err;
    }

    __debug( printf( "crypto: Reading PEM from input file pointer.\n" ); )
    if ( (pkey = PEM_read_PrivateKey(fp,NULL,NULL,NULL)) == NULL ) {
        fprintf( stderr, "crypto: Failed to read private key from file.\n" );
        goto __err;
    }

    fclose( fp );


    __debug( printf( "crypto: Creating digest context.\n" ); )
    if ( !(mdctx = EVP_MD_CTX_create()) )  goto __err;

    __debug( printf( "crypto: Initializing digest context.\n" ); )
    if ( EVP_DigestSignInit( mdctx, NULL, EVP_sha256(), NULL, pkey ) != 1 )  goto __err;

    __debug( printf( "crypto: Updating digest context.\n" ); )
    if ( EVP_DigestSignUpdate( mdctx, &p_packet->packet_hash[0], SPA_PACKET_HASH_SIZE ) != 1 )  goto __err;

    __debug( printf( "crypto: Getting final signature buffer length.\n" ); )
    if ( EVP_DigestSignFinal( mdctx, NULL, &slen ) != 1 )  goto __err;

    __debug( printf( "crypto: Allocating _predicted_ space for signature copy.\n" ); )
    if ( !(sig = (BYTE*)OPENSSL_malloc( sizeof(BYTE)*slen )) )  goto __err;

    __debug( printf( "crypto: Generating signature...\n" ); )
    if ( EVP_DigestSignFinal( mdctx, sig, &slen ) != 1 )  goto __err;
    rc = 1;

    // NOTE: slen gets updated in the final signing above. The initial malloc is to get the POTENTIAL signature size.
    if ( slen > SPA_PACKET_MAX_SIGNATURE_SIZE ) {
        fprintf( stderr, "crypto: The final signature exceeds maximum size of %d bytes.\n", SPA_PACKET_MAX_SIGNATURE_SIZE );
        goto __err;
    }

    __debug( printf( "crypto: Got valid packet signature with size of %lu bytes.\n", slen ); )
    p_packet->signature_length = (slen & 0xFFFFFFFF);

    __debug( printf( "crypto: Copying generated signature to packet buffer.\n" ); )
    memcpy( &p_packet->packet_signature[0], sig, sizeof(BYTE)*slen );


    __err:
    if ( sig != NULL )  OPENSSL_free( sig );
    if ( mdctx )  EVP_MD_CTX_destroy( mdctx );
    if ( pkey )  EVP_PKEY_free( pkey );

    if ( rc != 1 ) {
        __debug( printf( "~~~~~ Signature verification failed. Attempting to get why...\n" ); )

        char* openssl_err = (char*)calloc( 1, 128 );

        ERR_error_string_n( ERR_get_error(), openssl_err, 128 );
        __debug( printf( "~~~~~  ---> OpenSSL error: %s\n", openssl_err ); )

        free( openssl_err );
        return EXIT_FAILURE;
    }

    __debug( printf( "crypto: Packet signature is OK.\n" ); )
    return EXIT_SUCCESS;
}

