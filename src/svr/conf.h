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


#ifndef HEADER_CONF_H
#define HEADER_CONF_H



#include <err.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>
#include <openssl/x509.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "../../spa.h"
#include "action.h"



#define BASE_SHIFT 0x0001
#define SPA_CONF_FLAG_LOAD_SUCCESS ( BASE_SHIFT << 1 )
#define SPA_CONF_FLAG_ACCEPT_TERMS ( BASE_SHIFT << 2 )
#define SPA_CONF_FLAG_IPV4_ONLY ( BASE_SHIFT << 3 )
#define SPA_CONF_FLAG_IPV6_ONLY ( BASE_SHIFT << 4 )
#define SPA_CONF_FLAG_SKIP_INVALID_PKEY ( BASE_SHIFT << 5 )
#define SPA_CONF_FLAG_PREVENT_REPLAY ( BASE_SHIFT << 6 )
#define SPA_CONF_FLAG_GENERIC_ACTION ( BASE_SHIFT << 7 )
#define SPA_CONF_FLAG_NO_IPV4_MAPPING ( BASE_SHIFT << 8 )
#define SPA_CONF_FLAG_LOG_EXIT_CODES ( BASE_SHIFT << 9 )

#define SPA_CONF_MAX_STRLEN 512
#define SPA_CONF_SYSLOG_TAG_MAX_STRLEN 16

#define MAX_VALIDITY_WINDOW 86400
#define MIN_VALIDITY_WINDOW 10

// Shorthanding for brevity.
#define IS_CONFIG_LOADED \
    get_config_flag( SPA_CONF_FLAG_LOAD_SUCCESS ) == EXIT_SUCCESS
#define IS_IPV4_ONLY \
    get_config_flag( SPA_CONF_FLAG_IPV4_ONLY ) == EXIT_SUCCESS
#define IS_IPV6_ONLY \
    get_config_flag( SPA_CONF_FLAG_IPV6_ONLY ) == EXIT_SUCCESS
#define IS_DEBUG_MODE \
    spa_process.debug_mode == ON
#define IS_DAEMONIZED \
    spa_process.daemonized == ON



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
    BYTE config_path[PATH_MAX];
    BYTE pidfile_path[PATH_MAX];
    BYTE syslog_tag[SPA_CONF_SYSLOG_TAG_MAX_STRLEN+1];
    uint8_t debug_mode;
    uint8_t daemonized;
} __attribute__((__packed__)) spa_process;

// Retains meta-info about the application's configuration in a global structure.
//   These parameters are cleared and refreshed from the process information above every time the service re/starts.
struct spa_conf_meta_t {
    MODE mode;
    uint16_t flags;
    uint16_t bind_port;
    uint32_t validity_window;
    LOGLEVEL log_level;
    ACTION generic_action;
    BYTE bind_interface[IF_NAMESIZE];
    BYTE bind_address[INET6_ADDRSTRLEN];
} __attribute__((__packed__)) spa_conf;



int get_config_flag( uint16_t flag );
int set_config_flag( int on_or_off, uint16_t flag );
void clear_config();
int parse_config( BYTE* conf_path );
int check_config();



#endif
