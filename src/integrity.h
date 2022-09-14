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


#ifndef SPA_INTEGRITY_H
#define SPA_INTEGRITY_H

#include "spa.h"



// Initialize OpenSSL.
void openssl_init();
// Hashes an incoming SPA packet and returns the length of the resulting hash. If <= 0, error.
int hash_packet( unsigned char* dst_buffer, spa_packet_t* p_packet );



#endif   /* SPA_INTEGRITY_H */
