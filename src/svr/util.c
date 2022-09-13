/*
 * Miscellaneous utilities that are used in a few different implementations.
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


#include "util.h"



char* strtrim( char* str ) {
    char* end;
    while ( isspace((BYTE)*str) )  str++;
    if ( *str == 0 )  return str;
    end = str + strlen(str) - 1;
    while ( end > str && isspace((BYTE)*end) )  end--;
    end[1] = '\0';
    return str;
}

void strtolower( char* str ) {
    for ( char* x = str; *x; ++x )  *x = tolower( *x );
    return;
}

int is_bool_option_yes( char* value ) {
    if ( strnlen(value,3) < 3 )  return EXIT_FAILURE;
    char* lowerval = (char*)malloc( 4 );
    memset( lowerval, 0, 4 );
    memcpy( lowerval, value, 3 );
    lowerval[3] = '\0';
    strtolower( lowerval );
    int is_yes = ( strcmp( lowerval, "yes" ) == 0 ) ? EXIT_SUCCESS : EXIT_FAILURE;
    free( lowerval );
    return is_yes;
}

