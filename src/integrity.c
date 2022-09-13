/*
 * Common functions for SPA packet digests and OpenSSL initialization.
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

#include "integrity.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>



void openssl_init() {
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();
}



int sha256_digest( char* dest_buffer, const void* src_buffer, int buffer_len ) {
    int retcode = EXIT_FAILURE;

    SHA256_CTX sha_ctx;
    memset( &sha_ctx, 0, sizeof(SHA256_CTX) );

    if ( SHA256_Init( &sha_ctx ) != 1 )  return retcode;
    if ( SHA256_Update( &sha_ctx, src_buffer, buffer_len ) != 1 )  return retcode;
    if ( SHA256_Final( (unsigned char*)dest_buffer, &sha_ctx ) != 1 )  return retcode;

    return EXIT_SUCCESS;
}



int hash_packet( char* dst_buffer, spa_packet_t* p_packet ) {
    char hashed_content[SPA_PACKET_HASHED_SECTION_LEN];
    memcpy( &hashed_content[0], p_packet, SPA_PACKET_HASHED_SECTION_LEN );

    if (  EXIT_FAILURE == sha256_digest( dst_buffer, hashed_content, SPA_PACKET_HASHED_SECTION_LEN )  )
        return -1;

    return SHA256_DIGEST_LENGTH;
}
