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


#ifndef SPA_UTIL_H
#define SPA_UTIL_H



#include <ctype.h>
#include <string.h>
#include <stdlib.h>



char* strtrim( char* str );
void strtolower( char* str );
int is_bool_option_yes( char* value );



#endif   /* SPA_UTIL_H */
