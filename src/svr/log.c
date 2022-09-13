/*
 * Logging-related function implementations.
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


#include "include/log.h"



void syslog_init() {
    openlog( (const char*)&spa_process.syslog_tag[0], (LOG_CONS | LOG_NDELAY | LOG_PID), LOG_DAEMON );
    write_syslog( LOG_NOTICE, "Initializing.\n", NULL );
}



uint64_t generate_packet_id() {
    uint64_t r = 0;
    for ( int i = 0; i< 64; i+= RAND_MAX_WIDTH ) {
        r <<= RAND_MAX_WIDTH;
        r ^= (unsigned)rand();
    }
    return r;
}



void __write_log( uint64_t packet_id, LOG_TYPE log_type, int log_priority, const char* format, ... ) {
    va_list ap, ap2;
    va_start( ap, format );
    va_copy( ap2, ap );

    // If the packet_id is not 0, prepend it to the message.
    if ( packet_id > 0 ) {
        char prepend[512];
        memset( prepend, 0, 512 );
        snprintf( prepend, 512, "[%lu] %s", packet_id, format );
        format = prepend;
    }

    // Always send the message to syslog on three conditions:
    //   1: The message specifically says to.
    //   2: The process is running as a daemon.
    //   3: The configuration failed to load successfully and it's a normal log message (for pre-load instances).
    if ( (log_type & ERROR_SYSLOG) > 0
        || IS_DAEMONIZED
        || ( (log_type & ERROR_NONE) > 0 && get_config_flag( SPA_CONF_FLAG_LOAD_SUCCESS ) != EXIT_SUCCESS )
    )  vsyslog( log_priority, format, ap );

    // Regardless of daemonization and syslog params, write the message out to the appropriate stream.
    if ( log_type & ERROR_NONE )  vfprintf( stdout, format, ap2 );
    else if ( log_type & ERROR_APPEND )  verr( 1, format, ap2 );
    else if ( log_type & ERROR_NO_APPEND )  verrx( 1, format, ap2 );

    va_end( ap );
    va_end( ap2 );
}



# ifdef DEBUG
void print_hex( BYTE* data, size_t len ) {
    for ( size_t i = 0; i < len; i++ ) {
        if ( !(i % 8) )   fprintf(stderr, "  ");
        if ( !(i % 16) )  fprintf(stderr, "\n");
        fprintf(stderr, "%02x ", data[i]);
    }
    fprintf(stderr, "\n\n");
}
# endif
