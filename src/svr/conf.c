/*
 * Configuration-related function implementations.
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

#include "conf.h"

#include "log.h"
#include "users.h"
#include "action.h"

#include <err.h>
#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <linux/limits.h>
#include <openssl/x509.h>
#include <arpa/inet.h>



///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////
// Utility functions.
static char* strtrim( char* str ) {
    char* end;

    while ( isspace(*str) )  str++;
    if ( *str == 0 )  return str;

    end = str + strlen(str) - 1;
    while ( end > str && isspace(*end) )  end--;

    end[1] = '\0';
    return str;
}

static inline void strtolower( char* str ) {
    for ( char* x = str; *x; ++x )
        *x = tolower( *x );
}

static int is_bool_option_yes( char* value ) {
    if ( strnlen(value,3) < 3 )
        return EXIT_FAILURE;

    char lowerval[4] = {0};
    memset( &lowerval[0], 0, 4 );

    memcpy( lowerval, value, 3 );
    lowerval[3] = '\0';   // le paranoia

    strtolower( lowerval );

    int is_yes = ( 0 == strcmp( lowerval, "yes" ) ) ? EXIT_SUCCESS : EXIT_FAILURE;

    return is_yes;
}
///////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////



// TODO: Consider making the spa_conf value opaque.
// Get the value of a configuration bit/flag.
int SPAConf__get_flag( uint16_t flag ) {
    // this call encourages only one flag be sent through
    return (spa_conf.flags & flag) > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

// Set the value of a configuration bit on or off.
int SPAConf__set_flag( int on_or_off, uint16_t flag ) {
    __debuglog(
        write_log( "******* Setting configuration register flag |0x%04x| to |%s|\n",
            flag, (on_or_off > 0 ? "on" : "off") );
    )

    if ( on_or_off == ON ) {
        spa_conf.flags |= flag;   //on
    } else {
        spa_conf.flags &= ~flag;   //off
    }

    __debuglog(
        write_log( "******* Config flags: |0x%04x|\n", spa_conf.flags );
    )
    return EXIT_SUCCESS;
}



// Used to clear the global configuration settings and loaded data structures.
void SPAConf__clear() {
    SPAConf__set_flag( OFF, SPA_CONF_FLAG_LOAD_SUCCESS );

    memset( &spa_conf, 0, sizeof(struct spa_conf_meta_t) );
    memset( &spa_char_subs, 0, sizeof(struct spa_dynamic_substitutions_t) );

    SPAUser__clear();
    SPAAction__clear();
}



// See below.
static inline int SPAConf__check();

// Primary configuration parsing function. Should only be called one time, unless reloading the service.
int SPAConf__parse( const char* p_conf_path ) {
    FILE* fp_config_file;

    write_log( "Loading application configuration from '%s'.\n", p_conf_path );

    if (  NULL == (fp_config_file = fopen(p_conf_path, "r"))  ) {
        write_error_log( "~~~ The configuration file could not be read or opened.\n", NULL );
    }

    int line_num = 0;
    char linebuf[SPA_CONF_MAX_STRLEN];

    const char delim[2] = { '=', '\0' };
    const char keydelim[2] = { ':', '\0' };

    while ( !feof(fp_config_file) ) {
        line_num++;
        memset( linebuf, 0, SPA_CONF_MAX_STRLEN );

        // Read a line from the configuration file.
        fgets( linebuf, SPA_CONF_MAX_STRLEN, fp_config_file );

        // Any line starting with [#;] or less than three characters should be skipped.
        if ( linebuf[0] == '#' || linebuf[0] == ';' || strlen( linebuf ) < 3 )  continue;

        char* conf_val = strtok( linebuf, delim );   // left side of the '='
        if ( NULL == conf_val )  continue;
        char* key = strtrim( conf_val );

        conf_val = strtok( NULL, "" ); //delim );   // get the right side of the '='
        if ( NULL == conf_val )  continue;
        char* val = conf_val;

        // Trim the resulting value.
        val = strtrim( val );

        // Get the split key values as needed.
        char* keyx = (char*)calloc( 1, SPA_CONF_MAX_STRLEN );   // use max fgets length
        memcpy(  keyx, key, strnlen( key, SPA_CONF_MAX_STRLEN )  );
        keyx[SPA_CONF_MAX_STRLEN-1] = '\0';   // force null-termination

        char* keyleft = strtrim(  strtok( keyx, keydelim )  );
        if ( NULL == keyleft )  goto repeat_loop_cont;
        char* keyright = strtok( NULL, keydelim );
        // In the case of a key, don't really care if there are any :xyz:abc:123 strings after the first colon.

        // Sanity checks
        if ( strlen(key) < 1 || strlen(val) < 1 || strlen( keyleft ) < 1 ) {
            __debuglog( write_log( "+++ Skipping line; strlen of key, val, or keyleft is < 1.\n", NULL ); )
            goto repeat_loop_cont;
        } else {
            // Convert the key to lower-case.
            strtolower( key );
            strtolower( keyleft );
        }

        __debuglog( write_log( "+++ Reading key-value pair: |%s|,|%s| "
            "*** keysplit: |%s|:|%s|\n", key, val, keyleft, keyright ); )

        // Set the intended binding port.
        if (  0 == strcmp( key, "bind_port" )  ) {
            if ( spa_conf.bind_port != 0 ) {
                write_error_log( "Config line #%d: The bind_port option "
                    "can only be specified once.\n", line_num );
            }

            for ( int i = 0; i < strnlen(val,5); i++ ) {
                if (  !isdigit( val[i] )  ) {
                    write_error_log( "Config line #%d: Invalid port number: '%s'\n", line_num, val );
                }
            }

            spa_conf.bind_port = atoi( val );
            if ( spa_conf.bind_port < 1 || spa_conf.bind_port > UINT16_MAX ) {
                write_error_log( "Config line #%d: Bind port '%d' is out of range.\n",
                    line_num, spa_conf.bind_port );
            }

            __debuglog( write_log( "+++++ Bind port set to: |%d|\n", spa_conf.bind_port ); )
        }

        // Parse the intended program mode.
        else if (  0 == strcmp( key, "mode" )  ) {
            if ( spa_conf.mode != 0 ) {
                write_error_log( "Config line #%d: The mode cannot be defined multiple times.\n", line_num );
            }

            char lowerval[16] = {0}; // 16 is the max length of any mode
            memset( &lowerval[0], 0, 16 );
            memcpy( lowerval, val, strnlen(val,16) );
            lowerval[15] = '\0';
            strtolower( lowerval );

            if (  0 == strcmp( lowerval, "dead" )  )
                spa_conf.mode = dead;
            else if (  0 == strcmp( lowerval, "stealthy" )  )
                spa_conf.mode = stealthy;
            else if (  0 == strcmp( lowerval, "helpful" )  )
                spa_conf.mode = helpful;
            else if (  0 == strcmp( lowerval, "noisy" )  )
                spa_conf.mode = noisy;
            else {
                write_error_log( "Config line #%d: Invalid operating mode '%s'\n", line_num, lowerval );
            }

            __debuglog(  write_log( "+++++ Mode set to: |%d|\n", spa_conf.mode );  )
        }

        // Parse the log_level of the application.
        else if (  0 == strcmp( key, "log_level" )  ) {
            if ( spa_conf.log_level != 0 ) {
                write_error_log( "Config line #%d: The log_level cannot be "
                    "defined multiple times.\n", line_num );
            }

            for ( int i = 0; i < strnlen(val,1); i++ ) {
                if (  !isdigit( val[i] )  ) {
                    write_error_log( "Config line #%d: Invalid log_level number: '%s'\n", line_num, val );
                }
            }

            int log_level = atoi( val ) + 1;
            if (  log_level < quiet || log_level > debug  ) {
                write_error_log( "Config line #%d: Log level '%d' is out of "
                    "the valid configuration range.\n", line_num, log_level );
            }

            spa_conf.log_level = log_level;
            __debuglog(  write_log( "+++++ Set log level to '%d'\n", log_level-1 );  )
        }

        else if (  0 == strcmp( key, "log_exit_codes" )  ) {
            int state = is_bool_option_yes( val );
            SPAConf__set_flag(
                (state == EXIT_SUCCESS ? ON : OFF),
                SPA_CONF_FLAG_LOG_EXIT_CODES
            );

            __debuglog(
                write_log( "+++++ Logging exit codes is '%s'.\n",
                    (state == EXIT_SUCCESS ? "on" : "off") );
            )
        }

        // Parse the validity_window.
        else if (  0 == strcmp( key, "validity_window" )  ) {
            if ( 0 != spa_conf.validity_window ) {
                write_error_log( "Config line #%d: The validity_window option can "
                    "only be specified once.\n", line_num );
            }

            for ( int i = 0; i < strnlen(val,5); i++ ) {
                if (  !isdigit( val[i] )  ) {
                    write_error_log( "Config line #%d: Invalid validity window "
                        "number: '%s'\n", line_num, val );
                }
            }

            int window = atoi( val );
            if (  window > MAX_VALIDITY_WINDOW || window < MIN_VALIDITY_WINDOW  ) {
                write_error_log( "Config line #%d: Validity window of '%d' is out "
                    "of the range:  10 < x < 86400\n", line_num, window );
            }

            spa_conf.validity_window = window;
            __debuglog(
                write_log( "+++++ Validity window for SPA timestamps set to '%d'\n", window );
            )
        }

        // Get whether replays are being prevented.
        else if (  0 == strcmp( key, "prevent_replay" )  ) {
            int state = is_bool_option_yes( val );
            SPAConf__set_flag(
                (state == EXIT_SUCCESS ? ON : OFF),
                SPA_CONF_FLAG_PREVENT_REPLAY
            );

            __debuglog(
                write_log( "+++++ Prevent Replay feature is '%s'.\n",
                    (state == EXIT_SUCCESS ? "on" : "off") );
            )
        }

        // Get whether invalid pubkeys should be skipped. This should be defined BEFORE pubkeys if enabled.
        else if (  0 == strcmp( key, "skip_invalid_pubkeys" )  ) {
            int state = is_bool_option_yes( val );
            SPAConf__set_flag(
                (state == EXIT_SUCCESS ? ON : OFF),
                SPA_CONF_FLAG_SKIP_INVALID_PKEY
            );

            __debuglog(
                write_log( "+++++ Skip Invalid Public Keys feature is '%s'.\n",
                    (state == EXIT_SUCCESS ? "on" : "off") );
            )
        }

        // Get the generic_action, if defined, and set its flag. The ID of the generic action is meaningless.
        else if (  0 == strcmp( key, "generic_action" )  ) {
            if (
                   spa_conf.generic_action.action_id != 0
                || EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_GENERIC_ACTION )
            ) {
                write_error_log( "Config line #%d: The generic_action handler "
                    "can only be specified one time.\n", line_num );
            } else if (  strnlen( val, SPA_MAX_ACTION_CMD_LEN ) > (SPA_MAX_ACTION_CMD_LEN-1)  ) {
                write_error_log( "Config line #%d: The generic_action handler command length cannot be greater than"
                    " %d characters. Consider simplifying your handler.\n", line_num, SPA_MAX_ACTION_CMD_LEN-1 );
            }

            // Checks done. Load the action information into the meta config for the generic action.
            spa_conf.generic_action.action_id = (uint16_t)(ON & 0xFFFF);
            memcpy(  &((spa_conf.generic_action).command[0]), val, (strlen(val)+1)  );

            // Set the config flag to indicate a generic action is being used.
            SPAConf__set_flag( ON, SPA_CONF_FLAG_GENERIC_ACTION );
            __debuglog(
                write_log( "+++++ Enabled generic action with command sequence: '%s'\n", val );
            )

            write_syslog( LOG_WARNING, "WARNING: The generic_action handler is enabled. Actions and"
                " Autl policies will be disregarded, even if they were initially loaded!\n", NULL );
        }

        // Parse the list of users.
        else if (  0 == strcmp( key, "users" )  ) {
            const char users_separator[2] = { ',', '\0' };
            char* username = strtok( val, users_separator );

            while ( NULL != username ) {
                strtolower( username );   // always set username to lower-case

                if (  NULL != SPAUser__get( username )  ) {
                    write_error_log( "The user '%s' is already defined.\n", username );
                }

                spa_user_t* p_new_user = SPAUser__add( username );
                if ( NULL == p_new_user ) {
                    write_error_log( "There was a problem creating the user '%s'.\n", username );
                }

                p_new_user->valid_user = ON;   // assume the user will be valid by default
                // ^ the autl/pubkey/etc functions will do the work to mark a user as invalid (0x00) as needed
                __debuglog(
                    write_log( "+++++ Created user with name '%s'.\n", username );
                )

                // Rotate to the next username.
                username = strtok( NULL, users_separator );
            }

            if ( SPAUser__count() <= 0 ) {
                write_error_log( "No valid usernames were loaded.\n", NULL );
            }

            __debuglog(
                write_log( "+++++ Loaded %d TOTAL users.\n", SPAUser__count() );
            )
        }

        // Parse autls (requires 'users' to have been defined)
        else if (  0 == strcmp( keyleft, "autl" )  ) {
            if ( SPAUser__count() <= 0 ) {
                write_error_log( "Config line #%d: The 'users' option must be defined "
                    "BEFORE any autl entries.\n", line_num );
            } else if (  EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_GENERIC_ACTION )  ) {
                write_syslog( LOG_WARNING, "WARNING: Not loading autl on line #%d "
                    "because generic_action is set!\n", line_num );
                goto repeat_loop_cont;
            }

            spa_user_t* p_user = SPAUser__get( keyright );
            if ( NULL == p_user ) {
                write_error_log( "Config line #%d: policy user '%s' could not be loaded. "
                    "Is this user defined?", line_num, keyright );
            }

            __debuglog(
                write_log( "+++ Loading authorizations for '%s'.\n", p_user->username );
            )
            if (  EXIT_SUCCESS != SPAUser__load_autls( p_user, val )  ) {
                write_error_log( "Config line #%d: could not load autls for user.\n", line_num );
            }

            __debuglog(
                write_log( "+++++ User has total of %d authorization lists.\n", p_user->autl_count );
            )
        }

        // Parse pubkeys (requires 'users' to have been defined)
        else if (  0 == strcmp( keyleft, "pubkey" )  ) {
            if ( SPAUser__count() <= 0 ) {
                write_error_log( "Config line #%d: The 'users' option must be defined "
                    "BEFORE any pubkey entries.\n", line_num );
            }

            spa_user_t* p_user = SPAUser__get( keyright );
            if ( NULL == p_user ) {
                if (  EXIT_SUCCESS != SPAConf__get_flag( SPA_CONF_FLAG_SKIP_INVALID_PKEY )  ) {
                    write_error_log( "Config line %d: pubkey user could not be loaded. "
                        "Is this user defined?", line_num );
                } else {
                    write_syslog( LOG_WARNING, "WARNING: Config line %d: pubkey user "
                        "could not be loaded. Skipping...\n", line_num );
                    goto repeat_loop_cont;
                }
            }

            if (  strnlen( (const char*)(&(p_user->pkey_path[0])), PATH_MAX ) > 0  ) {
                if (  EXIT_SUCCESS != SPAConf__get_flag( SPA_CONF_FLAG_SKIP_INVALID_PKEY )  ) {
                    write_error_log( "Config line %d: user '%s' already has a pubkey defined.",
                        line_num, p_user->username );
                } else {
                    write_syslog( LOG_WARNING, "WARNING: Config line %d: user '%s' already has "
                        "a pubkey defined. Skipping...\n", line_num, p_user->username );
                    goto repeat_loop_cont;
                }
            }

            if (  EXIT_SUCCESS != SPAUser__load_pkey( p_user, val )  ) {
                if (  EXIT_SUCCESS != SPAConf__get_flag( SPA_CONF_FLAG_SKIP_INVALID_PKEY )  ) {
                    write_error_log( "Config line %d: could not load pubkey '%s' for user '%s'.",
                        line_num, val, p_user->username );
                } else {
                    write_syslog( LOG_WARNING, "WARNING: Config line %d: could not load pubkey "
                        "'%s' for user '%s'.\n", line_num, val, p_user->username );
                    goto repeat_loop_cont;
                }
            }

            __debuglog(
                write_log( "+++++ Loaded pubkey for user '%s'.\n", p_user->username );
            )
        }

        // Parse actions (requires the generic_action flag to have NOT been set; won't crash, just warn if it is)
        else if (  0 == strcmp( keyleft, "action" )  ) {
            if (  EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_GENERIC_ACTION )  ) {
                write_syslog( LOG_WARNING, "WARNING: Not loading action on line #%d "
                    "because generic_action is set!\n", line_num );
                goto repeat_loop_cont;
            } else if (  strnlen( val, SPA_MAX_ACTION_CMD_LEN+1 ) > SPA_MAX_ACTION_CMD_LEN  ) {
                write_error_log( "Config line #%d: Action command length is longer than "
                    "the limit of %d characters.\n", line_num, SPA_MAX_ACTION_CMD_LEN-1 );
            }
            val[SPA_MAX_ACTION_CMD_LEN-1] = '\0';   //enforce null-term

            for ( int i = 0; i < strnlen(keyright,5); i++ ) {
                if (  !isdigit( keyright[i] )  ) {
                    write_error_log( "Config line #%d: Action ID '%s' is not "
                        "a valid number.\n", line_num, keyright );
                }
            }

            uint16_t action_id = (uint16_t)(atoi( keyright ) & 0xFFFF);
            if (  action_id < 1 || action_id >= UINT16_MAX  ) {
                write_error_log( "Config line #%d: The provided action ID '%d' "
                    "is out of the valid range.\n", line_num, action_id );
            }

            // Make sure we're not over the actions limit, and the action_id is unique.
            if ( SPAAction__count() >= SPA_MAX_ACTIONS ) {
                write_error_log( "Config line #%d: Defined actions count exceeds "
                    "limit of %d actions.", line_num, SPA_MAX_ACTIONS );
            }

            // Make sure this isn't a duplicate action.
            if (  NULL != SPAAction__get( action_id )  ) {
                write_error_log( "Config line #%d: Action with ID '%d' is "
                    "already defined.", line_num, action_id );
            }

            if (  NULL == SPAAction__add( action_id, val )  ) {
                write_error_log( "Config line #%d: Unspecified error creating "
                    "action with ID '%d'.\n", line_num, action_id );
            }

            // Success.
            __debuglog(
                write_log( "+++++ Loaded action with ID '%d'.\n", action_id );
            )
        }

        else if (  0 == strcmp( keyleft, "sanitize_packet_data" )  ) {
            if (  keyright[0] == '\0' || val[0] == '\0'  ) {
                write_error_log( "Config line %d: Sanitization cannot translate "
                    "null (0x00) characters.\n", line_num );
            }

            __debuglog(
                write_log( "+++ Attempting to add packet_data sanitization for char '%c'.\n", keyright[0] );
            )
            if (  spa_char_subs.count >= SPA_MAX_ACTION_SUBSTITUTIONS  ) {
                write_error_log( "Config line %d: The amount of sanitization definitions"
                    " exceeds the limit of %d.\n", SPA_MAX_ACTION_SUBSTITUTIONS );
            }

            __debuglog(
                write_log( "+++++ Adding new substitution to static list.\n", NULL );
            )
            spa_subst_t repl = {0,0};
            repl.before = keyright[0];
            repl.after = val[0];

            __debuglog(
                write_log( "+++++++ Before: '%c', After: '%c'\n", repl.before, repl.after );
            )
            memcpy( &(spa_char_subs.list[spa_char_subs.count]), &repl, sizeof(spa_subst_t) );
            spa_char_subs.count++;
        }

        else if (  0 == strcmp( keyleft, "ipv4_only" )  ) {
            int state = is_bool_option_yes( val );
            SPAConf__set_flag(
                (state == EXIT_SUCCESS ? ON : OFF),
                SPA_CONF_FLAG_IPV4_ONLY
            );

            __debuglog(
                write_log( "+++++ IPv4-only feature is '%s'.\n",
                    (state == EXIT_SUCCESS ? "on" : "off") );
            )
        }

        else if (  0 == strcmp( keyleft, "ipv6_only" )  ) {
            int state = is_bool_option_yes( val );
            SPAConf__set_flag(
                (state == EXIT_SUCCESS ? ON : OFF),
                SPA_CONF_FLAG_IPV6_ONLY
            );

            __debuglog(
                write_log( "+++++ IPv6-only feature is '%s'.\n",
                    (state == EXIT_SUCCESS ? "on" : "off") );
            )
        }

        else if (  0 == strcmp( keyleft, "bind_interface" )  ) {
            if (  0 != strnlen( &(spa_conf.bind_interface[0]), IF_NAMESIZE )  ) {
                write_error_log( "Config line %d: The bind interface can only "
                    "be specified once.\n", line_num );
            } else if (  strnlen( &(spa_conf.bind_interface[0]), IF_NAMESIZE+1 ) > IF_NAMESIZE  ) {
                write_error_log( "Config line %d: Interface name exceeds max "
                    "size of %d characters.\n", line_num, IF_NAMESIZE-1 );
            }

            memcpy(  &(spa_conf.bind_interface[0]), val, strnlen( val, IF_NAMESIZE )  );
            spa_conf.bind_interface[IF_NAMESIZE-1] = '\0';   //force null-term
        }

        else if (  0 == strcmp( keyleft, "bind_address" )  ) {
            if (  0 != strnlen( &(spa_conf.bind_address[0]), INET6_ADDRSTRLEN )  ) {
                write_error_log( "Config line %d: The bind address can only "
                    "be specified once.\n", line_num );
            } else if (  strnlen( &(spa_conf.bind_address[0]), INET6_ADDRSTRLEN+1 ) > INET6_ADDRSTRLEN  ) {
                write_error_log( "Config line %d: Bind address exceeds max "
                    "size of %d characters.\n", line_num, INET6_ADDRSTRLEN-1 );
            }

            memcpy( &spa_conf.bind_address[0], val, strnlen(val,INET6_ADDRSTRLEN) );
            spa_conf.bind_address[INET6_ADDRSTRLEN-1] = '\0';   //force null-term
        }

        else if (  0 == strcmp( keyleft, "i_agree" )  ) {
            int state = is_bool_option_yes( val );
            SPAConf__set_flag(
                (state == EXIT_SUCCESS ? ON : OFF),
                SPA_CONF_FLAG_ACCEPT_TERMS
            );

            __debuglog(
                write_log( "+++++ Configuration/Terms agreement is '%s'.\n",
                (state == EXIT_SUCCESS ? "on" : "off") );
            )
        }

        else if (  0 == strcmp( keyleft, "map_ipv4_addresses" )  ) {
            int state = is_bool_option_yes( val );
            // Reversed thanks to double-negative language..
            SPAConf__set_flag(
                (state == EXIT_SUCCESS ? OFF : ON),
                SPA_CONF_FLAG_NO_IPV4_MAPPING
            );

            __debuglog(
                write_log( "+++++ IPv4-to-IPv6 address mapping (map_ipv4_addresses)"
                    " for SRCIP tokens is '%s'.\n", (state == EXIT_SUCCESS ? "on" : "off") );
            )
        }

        // Any other key in the configuration file should get the attention of the end user.
        else {
            write_error_log( "Config line #%d: Unrecognized configuration key '%s'."
                " Remove this value or comment it.\n\n", line_num, key );
        }

        repeat_loop_cont:
            free( keyx );
            __debuglog(  printf( "\n" );  )  //pretty for the terminal when run by CLI
    }

    SPAConf__set_flag( ON, SPA_CONF_FLAG_LOAD_SUCCESS );
    fclose( fp_config_file );

    return SPAConf__check();
}



// Returns whether or not the configuration registers and globals hold all necessary information for
//   the service to operate. This is strictly a double-check on the parse_config function.
static inline int SPAConf__check() {
    if (  (IS_DEBUG_MODE) || spa_conf.log_level >= debug  ) {
        printf( "\n##### Running configuration checks. #####\n" );
    }

    // terms acceptance
    if (  EXIT_SUCCESS != SPAConf__get_flag( SPA_CONF_FLAG_ACCEPT_TERMS )  ) {
        write_error_log( "ERROR: You must accept the terms of using this application by setting the"
            " 'i_agree' variable to 'yes' in the application configuration!\n", NULL );
    }

    // log_level
    if (  (IS_DEBUG_MODE)  ) {
        __normallog( write_log( "***** DEBUG option is set. Forcing debug log-level.\n", NULL ); )
        spa_conf.log_level = debug;
    } else if ( spa_conf.log_level < quiet ) {
        __debuglog( write_log( "***** Log level defaulted to 'normal'.\n", NULL ); )
        spa_conf.log_level = normal;
    }

    // bind_port
    if ( spa_conf.bind_port <= 0 ) {
        __quietlog(
            write_syslog( LOG_WARNING, "WARNING: Missing bind_port config option."
                " Defaulting to port %d.\n", SPA_DEFAULT_BIND_PORT );
        )
        spa_conf.bind_port = SPA_DEFAULT_BIND_PORT;
    }

    // bind_interface
    if (  0 == strnlen( spa_conf.bind_interface, 3 )  ) {
        __quietlog(
            write_syslog( LOG_WARNING, "WARNING: Missing bind_interface config option."
                " Defaulting to 'any' interface.\n", NULL );
        )
        memcpy( &(spa_conf.bind_interface[0]), "any", 4 );
    }

    // bind_address
    if (  0 == strnlen( (const char*)spa_conf.bind_address, 3 )  ) {
        __quietlog(
            write_syslog( LOG_WARNING, "WARNING: Missing bind_address config option."
                " Defaulting to 'any' address.\n", NULL );
        )
        memcpy( &(spa_conf.bind_address[0]), "any", 4 );
    }

    // ip version restrictions
    if (  (IS_IPV4_ONLY) && (IS_IPV6_ONLY)  ) {
        write_error_log( "Both IPv4- and IPv6-only options are enabled."
            " Only one of these can be set to 'yes'.\n", NULL );
    }
    // check the bind address against the requested version type, if not set to 'any'
    if (  0 != strncmp( &(spa_conf.bind_address[0]), "any", 4 )  ) {
        char* p_dummyaddr = (char*)calloc( 1, sizeof(struct in6_addr) );

        int is4 = inet_pton( AF_INET, &(spa_conf.bind_address[0]), p_dummyaddr );
        memset( p_dummyaddr, 0, sizeof(struct in6_addr) );

        int is6 = inet_pton( AF_INET6, &(spa_conf.bind_address[0]), p_dummyaddr );

        // Check the restriction against the result of the address interpretation.
        if (  is4 < 1 && (IS_IPV4_ONLY)  ) {
            write_error_log( "IPv4-only mode is set, but the bind_address does not"
                " appear to be a valid IPv4 address.\n", NULL );
        } else if (  is6 < 1 && (IS_IPV6_ONLY)  ) {
            write_error_log( "IPv6-only mode is set, but the bind_address does not"
                " appear to be a valid IPv6 address.\n", NULL );
        } else {
            if (  is4 < 1 && is6 < 1  ) {
                write_error_log( "The bind_address value '%s' does not appear to be"
                    " a valid IPv4 or IPv6 address.\n", spa_conf.bind_address );
            }
        }

        // If the bind address is an IPv4 address, the IPV4_ONLY flag _MUST_ be set for the rest
        //   of the application to operate properly. IPv6 is the assumed default, so this doesn't
        //   require separate behavior.
        if ( is4 == 1 )
            SPAConf__set_flag( ON, SPA_CONF_FLAG_IPV4_ONLY );

        free( p_dummyaddr );
    }

    // mode
    if ( spa_conf.mode <= 0 ) {
        write_error_log( "The required 'mode' configuration option is not defined.\n", NULL );
    }

    // validity_window
    if ( spa_conf.validity_window <= 0 ) {
        write_error_log( "The required 'validity_window' configuration option is not defined.\n", NULL );
    }

    // prevent_replay - WARN when disabled
    if (  EXIT_SUCCESS != SPAConf__get_flag( SPA_CONF_FLAG_PREVENT_REPLAY )  ) {
        __quietlog(
            write_syslog( LOG_WARNING, "WARNING: Replay prevention is not actively being"
                " enforced. This is dangerous and can lead to vulnerabilities!\n", NULL );
        )
    }

    // users
    if (  SPAUser__count() <= 0  ) {
        write_error_log( "The required 'users' configuration option is not defined, or no valid"
            " users were loaded. The service cannot run.\n", NULL );
    }

    // skip_invalid_pubkeys
    if (  EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_SKIP_INVALID_PKEY )  ) {
        __quietlog(
            write_syslog( LOG_WARNING, "WARNING: The 'skip_invalid_pubkeys' option is enabled."
                " This can unintentionally lead to configured users failing to load.\n", NULL );
        )
    }

    // action:X
    if (  SPAAction__count() <= 0 && EXIT_SUCCESS != SPAConf__get_flag( SPA_CONF_FLAG_GENERIC_ACTION )  ) {
        write_error_log( "No valid actions have been loaded, and the generic_action handler is not set.\n", NULL );
    } else if (  SPAAction__count() > 0 && EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_GENERIC_ACTION )  ) {
        __quietlog(
            write_syslog( LOG_WARNING, "WARNING: The 'generic_action' handler is enabled, but some"
                " valid actions have been loaded which will all redirect to the generic_action handler.\n", NULL );
        )
    }

    // generic_action check
    if (  EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_GENERIC_ACTION )  ) {
        if (  ON != spa_conf.generic_action.action_id  ) {
            write_error_log( "The 'generic_action' handler is enabled, but the action"
                " doesn't appear to be valid.\n", NULL );
        }
    }

    // pubkey check -- sweep all users and if skip_invalid_pubkeys isn't enabled, throw an error on missing keys
    spa_user_t* p_user_base = SPAUser__get_array();   // start at the base of the array
    for ( size_t x = 0; x < SPAUser__count(); x++  ) {
        spa_user_t* p_user = (p_user_base + x);

        __debuglog(
            printf( "*** Checking pubkey validity for user '%s'.\n", p_user->username );
        )
        int rc = SPAUser__get_pkey( p_user );
        if (
               EXIT_SUCCESS != SPAConf__get_flag( SPA_CONF_FLAG_SKIP_INVALID_PKEY )
            && EXIT_SUCCESS != rc
        ) {
            write_error_log( "The public key for user '%s' is not valid and skip_invalid_pubkeys is not enabled."
                " Either remove the user, enable the option, or fix the public key.\n", p_user->username );
        }
        __debuglog(  printf( "***** Public key OK\n" );  )

        // Also check: autl -- sweep all users for autl entries, warn on users without any authorized functions
        __debuglog(
            printf( "*** Also checking authorizations for this user.\n" );
        )
        if (  p_user->autl_count <= 0  ) {
            write_syslog( LOG_WARNING, "WARNING: User '%s' does not have any defined authorizations"
                " and will not be able to perform any SPA functions.\n", p_user->username );
        } else {
            __debuglog(  printf( "***** User AUTL looks OK.\n" );  )
        }
    }

    // map_ipv4_addresses -- Turn off the configuration flag if the socket is not using an 'any' binding
    if (  EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_NO_IPV4_MAPPING )  ) {
        if (  0 != strncmp( &(spa_conf.bind_address[0]), "any", 4 )  ) {
            __debuglog( printf( "***** Socket is bound to a specific address and"
                " map_ipv4_addresses was disabled. Forcing enabled.\n" ); )
            SPAConf__set_flag( OFF, SPA_CONF_FLAG_NO_IPV4_MAPPING );
        } else if (  (IS_IPV4_ONLY) || (IS_IPV6_ONLY)  ) {
            __debuglog(
                printf( "***** Either ipv4_only or ipv6_only is set to 'yes' but"
                    " map_ipv4_addresses was disabled. Forcing enabled.\n" );
            )
            SPAConf__set_flag( OFF, SPA_CONF_FLAG_NO_IPV4_MAPPING );
        }
    }

    // done
    __debuglog(
        printf( "\n# END configuration checks. #\n###########################################\n\n" );
    )
    return EXIT_SUCCESS;
}
