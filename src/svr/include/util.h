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


#ifndef HEADER_UTIL_H
#define HEADER_UTIL_H



#include <ctype.h>
#include <string.h>
#include <stdlib.h>



// Redefined; no sense in importing spa.h just for this.
typedef unsigned char BYTE;

char* strtrim( char* str );
void strtolower( char* str );
int is_bool_option_yes( char* value );



#endif
