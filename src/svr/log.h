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


#ifndef SPA_LOG_H
#define SPA_LOG_H



// LOGGING MACROS:
//   log: Used to write to the terminal, but also writes an INFO-level message to syslog when daemonized
//   syslog: Always send the message to syslog, whether run by CLI or not
//   error_log: Write the error message to syslog and exit with a formatted message and no extra output
//   error_log_append: Same as error_log except it will also get the error string

#define write_log( fmt, ... ) \
    SPALog__write( 0, ERROR_NONE, LOG_INFO, fmt, __VA_ARGS__ );
#define write_syslog( prio, fmt, ... ) \
    SPALog__write( 0, (ERROR_NONE | ERROR_SYSLOG), prio, fmt, __VA_ARGS__ );
#define write_error_log( fmt, ... ) \
    SPALog__write( 0, (ERROR_NO_APPEND | ERROR_SYSLOG), LOG_ERR, fmt, __VA_ARGS__ );
#define write_error_log_append( fmt, ... ) \
    SPALog__write( 0, (ERROR_APPEND | ERROR_SYSLOG), LOG_ERR, fmt, __VA_ARGS__ );

// NOTE: packet error logs do NOT send the error types through, since that would
//   halt the application from the thread.
#define packet_log( pktid, fmt, ... ) \
    SPALog__write( pktid, ERROR_NONE, LOG_INFO, fmt, __VA_ARGS__ );
#define packet_syslog( pktid, prio, fmt, ... ) \
    SPALog__write( pktid, (ERROR_NONE | ERROR_SYSLOG), prio, fmt, __VA_ARGS__ );
#define packet_error_log( pktid, fmt, ... ) \
    SPALog__write( pktid, (ERROR_NONE | ERROR_SYSLOG), LOG_ERR, fmt, __VA_ARGS__ );

// Log levels should only EVER be checked _AFTER_ the config has been loaded and validated.
#define __debuglog( ... ) \
    if ( IS_DEBUG_MODE || (IS_CONFIG_LOADED && spa_conf.log_level >= debug) )  { __VA_ARGS__ }
#define __verboselog( ... ) \
    if ( IS_CONFIG_LOADED && spa_conf.log_level >= verbose )  { __VA_ARGS__ }
#define __normallog( ... ) \
    if ( IS_CONFIG_LOADED && spa_conf.log_level >= normal )  { __VA_ARGS__ }
#define __quietlog( ... ) \
    if ( IS_CONFIG_LOADED && spa_conf.log_level >= quiet )  { __VA_ARGS__ }



// Define a set of log types to indicate the appropriate action.
typedef enum spa_log_type_t {
    // Normal message; no error
    ERROR_NONE      = (1 << 1),
    // Append the strerror information to the string
    ERROR_APPEND    = (1 << 2),
    // Create your own error string (no strerror annotations)
    ERROR_NO_APPEND = (1 << 3),
    // Send the message to syslog as well.
    ERROR_SYSLOG    = (1 << 4)
} LOG_TYPE;



// SPA Logging functions.
void SPALog__write(
    uint64_t packet_id,
    LOG_TYPE log_type,
    int log_priority,
    const char* format,
    ...
);



#endif   /* SPA_LOG_H */
