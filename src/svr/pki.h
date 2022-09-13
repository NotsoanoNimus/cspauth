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


#ifndef SPA_PKI_H
#define SPA_PKI_H

#include "users.h"



// Load an X509 public key from a filename.
int load_user_pkey( spa_user_t* p_user_data, char* p_pem_filename );
// Get the validity of a pkey without saving/changing anything.
int get_user_pkey( spa_user_t* p_user_data );



#endif   /* SPA_PKI_H */
