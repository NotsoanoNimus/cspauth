/*
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


#ifndef PKI_HEADER_H
#define PKI_HEADER_H



#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include "../../spa.h"
#include "users.h"



// Load an X509 public key from a filename.
int load_user_pkey( USER* p_user_data, BYTE* p_pem_filename );
// Get the validity of a pkey without saving/changing anything.
int get_user_pkey( USER* p_user_data );



#endif
