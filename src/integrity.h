/*
 * Definitions for shared client/server packet digest and OpenSSL functions.
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


#ifndef HEADER_INTEGRITY_H
#define HEADER_INTEGRITY_H



#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "spa.h"



// Initialize OpenSSL.
void openssl_init();
// Get a SHA256 hash digest.
int sha256_digest( BYTE* dest_buffer, const void* src_buffer, int buffer_len );
// Hashes an incoming SPA packet and returns the length of the resulting hash. If <= 0, error.
int hash_packet( BYTE* dst_buffer, struct spa_packet_t* p_packet );
// Signs a packet and stores its signature on the pointed packet.
int sign_packet( BYTE* key_file, struct spa_packet_t* p_packet, int* is_debug );



#endif
