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


#ifndef SPA_CONF_H
#define SPA_CONF_H

#include "../spa.h"
#include "action.h"



// Global daemon configuration flags.
#define SPA_CONF_FLAG_LOAD_SUCCESS      ( 1 << 1 )
#define SPA_CONF_FLAG_ACCEPT_TERMS      ( 1 << 2 )
#define SPA_CONF_FLAG_IPV4_ONLY         ( 1 << 3 )
#define SPA_CONF_FLAG_IPV6_ONLY         ( 1 << 4 )
#define SPA_CONF_FLAG_SKIP_INVALID_PKEY ( 1 << 5 )
#define SPA_CONF_FLAG_PREVENT_REPLAY    ( 1 << 6 )
#define SPA_CONF_FLAG_GENERIC_ACTION    ( 1 << 7 )
#define SPA_CONF_FLAG_NO_IPV4_MAPPING   ( 1 << 8 )
#define SPA_CONF_FLAG_LOG_EXIT_CODES    ( 1 << 9 )

#define SPA_CONF_MAX_STRLEN 512
#define SPA_CONF_SYSLOG_TAG_MAX_STRLEN 16

#define MAX_VALIDITY_WINDOW 86400
#define MIN_VALIDITY_WINDOW 10

// Shorthanding for brevity.
#define IS_CONFIG_LOADED \
    EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_LOAD_SUCCESS )
#define IS_IPV4_ONLY \
    EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_IPV4_ONLY )
#define IS_IPV6_ONLY \
    EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_IPV6_ONLY )
#define IS_DEBUG_MODE \
    ON == spa_process.debug_mode
#define IS_DAEMONIZED \
    ON == spa_process.daemonized



// The available SPA operating modes defined in the configuration file.
typedef enum spa_mode {
    dead = 1,
    stealthy,
    helpful,
    noisy
} MODE;

// Application log levels. Defined in an enum so more granularity can be dynamically added later as needed.
typedef enum spa_log_level {
    quiet = 1,
    normal,
    verbose,
    debug
} LOGLEVEL;


// Retains meta-info about the configuration and process in a global structure.
struct spa_process_meta_t {
    char config_path[PATH_MAX];
    char pidfile_path[PATH_MAX];
    char syslog_tag[SPA_CONF_SYSLOG_TAG_MAX_STRLEN+1];
    uint8_t debug_mode;
    uint8_t daemonized;
} spa_process;

// Retains meta-info about the application's configuration in a global structure.
//   These parameters are cleared and refreshed from the process information above every time the service re/starts.
struct spa_conf_meta_t {
    MODE mode;
    uint16_t flags;
    uint16_t bind_port;
    uint32_t validity_window;
    LOGLEVEL log_level;
    spa_action_t generic_action;
    char bind_interface[IF_NAMESIZE];
    char bind_address[INET6_ADDRSTRLEN];
} spa_conf;



// Functions for accessing and manipulating the loaded SPA configuration.
int SPAConf__get_flag( uint16_t flag );
int SPAConf__set_flag( int on_or_off, uint16_t flag );
void SPAConf__clear();
int SPAConf__parse( const char* conf_path );



#endif   /* SPA_CONF_H */
