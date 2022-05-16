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

#include "include/conf.h"
#include "include/log.h"
#include "include/pki.h"
#include "include/util.h"
#include "include/users.h"
#include "include/action.h"



// TODO: Consider making the spa_conf value opaque.
// Get the value of a configuration bit/flag.
int get_config_flag( uint16_t flag ) {
	// this call encourages only one flag be sent through
	return (spa_conf.flags & flag) > 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

// Set the value of a configuration bit on or off.
int set_config_flag( int on_or_off, uint16_t flag ) {
	__debuglog( write_log( "******* Setting configuration register flag |0x%04x| to |%s|\n", flag, (on_or_off > 0 ? "on" : "off") ); )
	if ( on_or_off == ON ) {
		spa_conf.flags |= flag;   //on
	} else {
		spa_conf.flags &= ~flag;   //off
	}
	__debuglog( write_log( "******* Config flags: |0x%04x|\n", spa_conf.flags ); )
	return EXIT_SUCCESS;
}



// Used to clear the global configuration settings.
void clear_config() {
	set_config_flag( OFF, SPA_CONF_FLAG_LOAD_SUCCESS );
	memset( &spa_conf, 0, sizeof(struct spa_conf_meta_t) );
	memset( &spa_char_subs, 0, sizeof(struct spa_dynamic_substitutions_t) );
	clear_all_users();
	clear_all_actions();
}



// Returns whether or not the configuration registers and globals hold all necessary information for
//   the service to operate. This is strictly a double-check on the parse_config function.
// TODO
int check_config() {
	if ( (IS_DEBUG_MODE) || spa_conf.log_level >= debug ) {
		printf( "\n##### Running configuration checks. #####\n" );
	}

	// terms acceptance
	if ( get_config_flag( SPA_CONF_FLAG_ACCEPT_TERMS ) != EXIT_SUCCESS ) {
		write_error_log( "ERROR: You must accept the terms of using this application by setting the"
			" 'i_agree' variable to 'yes' in the application configuration!\n", NULL );
	}

	// log_level
	if ( (IS_DEBUG_MODE) ) {
		__normallog( write_log( "***** DEBUG option is set. Forcing debug log-level.\n", NULL ); )
		spa_conf.log_level = debug;
	} else if ( spa_conf.log_level < quiet ) {
		__debuglog( write_log( "***** Log level defaulted to 'normal'.\n", NULL ); )
		spa_conf.log_level = normal;
	}

	// bind_port
	if ( spa_conf.bind_port <= 0 ) {
		__quietlog( write_syslog( LOG_WARNING, "WARNING: Missing bind_port config option."
			" Defaulting to port %d.\n", SPA_DEFAULT_BIND_PORT ); )
		spa_conf.bind_port = SPA_DEFAULT_BIND_PORT;
	}

	// bind_interface
	if ( strnlen( (const char*)spa_conf.bind_interface, 3 ) == 0 ) {
		__quietlog( write_syslog( LOG_WARNING, "WARNING: Missing bind_interface config option."
			" Defaulting to 'any' interface.\n", NULL ); )
		memcpy( &spa_conf.bind_interface[0], (BYTE*)"any", 4 );
	}

	// bind_address
	if ( strnlen( (const char*)spa_conf.bind_address, 3 ) == 0 ) {
		__quietlog( write_syslog( LOG_WARNING, "WARNING: Missing bind_address config option."
			" Defaulting to 'any' address.\n", NULL ); )
		memcpy( &spa_conf.bind_address[0], (BYTE*)"any", 4 );
	}

	// ip version restrictions
	if ( (IS_IPV4_ONLY) && (IS_IPV6_ONLY) ) {
		write_error_log( "Both IPv4- and IPv6-only options are enabled."
			" Only one of these can be set to 'yes'.\n", NULL );
	}
	// check the bind address against the requested version type, if not set to 'any'
	if ( strncmp( (const char*)&spa_conf.bind_address[0], "any", 4 ) != 0 ) {
		BYTE* dummyaddr = (BYTE*)malloc( sizeof(struct in6_addr) );
		memset( dummyaddr, 0, sizeof(struct in6_addr) );

		int is4 = inet_pton( AF_INET, (const char*)&spa_conf.bind_address[0], dummyaddr );
		memset( dummyaddr, 0, sizeof(struct in6_addr) );
		int is6 = inet_pton( AF_INET6, (const char*)&spa_conf.bind_address[0], dummyaddr );

		// Check the restriction against the result of the address interpretation.
		if ( is4 < 1 && (IS_IPV4_ONLY) ) {
			write_error_log( "IPv4-only mode is set, but the bind_address does not"
				" appear to be a valid IPv4 address.\n", NULL );
		} else if ( is6 < 1 && (IS_IPV6_ONLY) ) {
			write_error_log( "IPv6-only mode is set, but the bind_address does not"
				" appear to be a valid IPv6 address.\n", NULL );
		} else {
			if ( is4 < 1 && is6 < 1 )
				write_error_log( "The bind_address value '%s' does not appear to be"
					" a valid IPv4 or IPv6 address.\n", spa_conf.bind_address );
		}

		// If the bind address is an IPv4 address, the IPV4_ONLY flag _MUST_ be set for the rest
		//   of the application to operate properly. IPv6 is the assumed default, so this doesn't
		//   require separate behavior.
		if ( is4 == 1 )  set_config_flag( ON, SPA_CONF_FLAG_IPV4_ONLY );

		free( dummyaddr );
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
	if ( get_config_flag( SPA_CONF_FLAG_PREVENT_REPLAY ) != EXIT_SUCCESS ) {
		__quietlog( write_syslog( LOG_WARNING, "WARNING: Replay prevention is not actively being"
			" enforced. This is dangerous and can lead to vulnerabilities!\n", NULL ); )
	}

	// users
	if ( get_user_count() <= 0 ) {
		write_error_log( "The required 'users' configuration option is not defined, or no valid"
			" users were loaded. The service cannot run.\n", NULL );
	}

	// skip_invalid_pubkeys
	if ( get_config_flag( SPA_CONF_FLAG_SKIP_INVALID_PKEY ) == EXIT_SUCCESS ) {
		__quietlog( write_syslog( LOG_WARNING, "WARNING: The 'skip_invalid_pubkeys' option is enabled."
			" This can unintentionally lead to configured users failing to load.\n", NULL ); )
	}

	// action:X
	if ( get_actions_count() <= 0 && get_config_flag( SPA_CONF_FLAG_GENERIC_ACTION ) != EXIT_SUCCESS ) {
		write_error_log( "No valid actions have been loaded, and the generic_action handler is not set.\n", NULL );
	} else if ( get_actions_count() > 0 && get_config_flag( SPA_CONF_FLAG_GENERIC_ACTION ) == EXIT_SUCCESS ) {
		__quietlog( write_syslog( LOG_WARNING, "WARNING: The 'generic_action' handler is enabled, but some"
			" valid actions have been loaded which will all redirect to the generic_action handler.\n", NULL ); )
	}

	// generic_action check
	if ( get_config_flag( SPA_CONF_FLAG_GENERIC_ACTION ) == EXIT_SUCCESS ) {
		if ( spa_conf.generic_action.action_id != ON ) {
			write_error_log( "The 'generic_action' handler is enabled, but the action"
				" doesn't appear to be valid.\n", NULL );
		}
	}

	// pubkey check -- sweep all users and if skip_invalid_pubkeys isn't enabled, throw an error on missing keys
	for ( LIST_NODE* p_ux = get_user_head(); p_ux != NULL; p_ux = p_ux->next ) {
		USER* p_user = ((USER*)(p_ux->node));

		__debuglog( printf( "*** Checking pubkey validity for user '%s'.\n", p_user->username ); )
		int rc = get_user_pkey( p_user );
		if ( get_config_flag( SPA_CONF_FLAG_SKIP_INVALID_PKEY ) != EXIT_SUCCESS && rc != EXIT_SUCCESS ) {
			write_error_log( "The public key for user '%s' is not valid and skip_invalid_pubkeys is not enabled."
				" Either remove the user, enable the option, or fix the public key.\n", p_user->username );
		}
		__debuglog( printf( "***** Public key OK\n" ); )

		// Also check: autl -- sweep all users for autl entries, warn on users without any authorized functions
		__debuglog( printf( "*** Also checking authorizations for this user.\n" ); )
		if ( list_get_count( p_user->autl ) <= 0 ) {
			write_syslog( LOG_WARNING, "WARNING: User '%s' does not have any defined authorizations"
				" and will not be able to perform any SPA functions.\n", p_user->username );
		} else {
			__debuglog( printf( "***** User AUTL looks OK.\n" ); )
		}
	}

	// map_ipv4_addresses -- Turn off the configuration flag if the socket is not using an 'any' binding
	if ( get_config_flag( SPA_CONF_FLAG_NO_IPV4_MAPPING ) == EXIT_SUCCESS ) {
		if ( strncmp( (const char*)&spa_conf.bind_address[0], "any", 4 ) != 0 ) {
			__debuglog( printf( "***** Socket is bound to a specific address and"
				" map_ipv4_addresses was disabled. Forcing enabled.\n" ); )
			set_config_flag( OFF, SPA_CONF_FLAG_NO_IPV4_MAPPING );
		} else if ( (IS_IPV4_ONLY) || (IS_IPV6_ONLY) ) {
			__debuglog( printf( "***** Either ipv4_only or ipv6_only is set to 'yes' but"
				" map_ipv4_addresses was disabled. Forcing enabled.\n" ); )
			set_config_flag( OFF, SPA_CONF_FLAG_NO_IPV4_MAPPING );
		}
	}


	__debuglog( printf( "\n# END configuration checks. #\n###########################################\n\n" ); )
	return EXIT_SUCCESS;
}



// Primary configuration parsing function. Should only be called one time, unless reloading the service.
int parse_config( BYTE* conf_path ) {
	FILE* config_file_h;

	write_log( "Loading application configuration from '%s'.\n", conf_path );

	if ( (config_file_h = fopen((const char*)conf_path, "r")) == NULL ) {
		write_error_log( "~~~ The configuration file could not be read or opened.\n", NULL );
	}

	int line_num = 0;
	char linebuf[SPA_CONF_MAX_STRLEN];
	const char delim[2] = { '=', '\0' };
	const char keydelim[2] = { ':', '\0' };
	while ( !feof(config_file_h) ) {
		line_num++;
		memset( linebuf, 0, SPA_CONF_MAX_STRLEN );
		// Read a line from the configuration file.
		fgets( linebuf, SPA_CONF_MAX_STRLEN, config_file_h );

		// Any line starting with [#;] or less than three characters should be skipped.
		if ( linebuf[0] == '#' || linebuf[0] == ';' || strlen( linebuf ) < 3 )  continue;

		char* conf_val = strtok( linebuf, delim );   // left side of the '='
		if ( conf_val == NULL )  continue;
		char* key = strtrim( conf_val );

		conf_val = strtok( NULL, "" ); //delim );   // get the right side of the '='
		if ( conf_val == NULL )  continue;
		char* val = conf_val;

		// Trim the resulting value.
		val = strtrim( val );

		// Get the split key values as needed.
		char* keyx = (char*)malloc( SPA_CONF_MAX_STRLEN );   // use max fgets length
		memset( keyx, 0, SPA_CONF_MAX_STRLEN );
		memcpy( keyx, key, strnlen(key,SPA_CONF_MAX_STRLEN) );
		keyx[SPA_CONF_MAX_STRLEN-1] = '\0';   // force null-termination
		char* keyleft = strtrim( strtok( keyx, keydelim ) );
		if ( keyleft == NULL )  goto repeat_loop_cont;
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
		if ( strcmp( key, "bind_port" ) == 0 ) {
			if ( spa_conf.bind_port != 0 ) {
				write_error_log( "Config line #%d: The bind_port option can only be specified once.\n", line_num );
			}

			for ( int i = 0; i < strnlen(val,5); i++ ) {
				if ( !isdigit( val[i] ) ) {
					write_error_log( "Config line #%d: Invalid port number: '%s'\n", line_num, val );
				}
			}

			spa_conf.bind_port = atoi( val );
			if ( spa_conf.bind_port < 1 || spa_conf.bind_port > UINT16_MAX ) {
				write_error_log( "Config line #%d: Bind port '%d' is out of range.\n", line_num, spa_conf.bind_port );
			}

			__debuglog( write_log( "+++++ Bind port set to: |%d|\n", spa_conf.bind_port ); )
		}

		// Parse the intended program mode.
		else if ( strcmp( key, "mode" ) == 0 ) {
			if ( spa_conf.mode != 0 ) {
				write_error_log( "Config line #%d: The mode cannot be defined multiple times.\n", line_num );
			}

			char* lowerval = (char*)malloc( 16 );   //allocate what's basically the maxlen of any mode
			memset( lowerval, 0, 16 );
			memcpy( lowerval, val, strnlen(val,16) );
			lowerval[15] = '\0';
			strtolower( lowerval );

			if ( strcmp( lowerval, "dead" ) == 0 )
				spa_conf.mode = dead;
			else if ( strcmp( lowerval, "stealthy" ) == 0 )
				spa_conf.mode = stealthy;
			else if ( strcmp( lowerval, "helpful" ) == 0 )
				spa_conf.mode = helpful;
			else if ( strcmp( lowerval, "noisy" ) == 0 )
				spa_conf.mode = noisy;
			else {
				write_error_log( "Config line #%d: Invalid operating mode '%s'\n", line_num, lowerval );
			}

			__debuglog( write_log( "+++++ Mode set to: |%d|\n", spa_conf.mode ); )
			free( lowerval );
		}

		// Parse the log_level of the application.
		else if ( strcmp( key, "log_level" ) == 0 ) {
			if ( spa_conf.log_level != 0 ) {
				write_error_log( "Config line #%d: The log_level cannot be defined multiple times.\n", line_num );
			}

			for ( int i = 0; i < strnlen(val,1); i++ ) {
				if ( !isdigit( val[i] ) ) {
					write_error_log( "Config line #%d: Invalid log_level number: '%s'\n", line_num, val );
				}
			}

			int log_level = atoi( val ) + 1;
			if ( log_level < quiet || log_level > debug ) {
				write_error_log( "Config line #%d: Log level '%d' is out of the valid configuration range.\n", line_num, log_level );
			}

			spa_conf.log_level = log_level;
			__debuglog( write_log( "+++++ Set log level to '%d'\n", log_level-1 ); )
		}

		else if ( strcmp( key, "log_exit_codes" ) == 0 ) {
			int state = is_bool_option_yes( val );
			set_config_flag( (state == EXIT_SUCCESS ? ON : OFF), SPA_CONF_FLAG_LOG_EXIT_CODES );
			__debuglog( write_log( "+++++ Logging exit codes is '%s'.\n", (state == EXIT_SUCCESS ? "on" : "off") ); )
		}

		// Parse the validity_window.
		else if ( strcmp( key, "validity_window" ) == 0 ) {
			if ( spa_conf.validity_window != 0 ) {
				write_error_log( "Config line #%d: The validity_window option can only be specified once.\n", line_num );
			}

			for ( int i = 0; i < strnlen(val,5); i++ ) {
				if ( !isdigit( val[i] ) ) {
					write_error_log( "Config line #%d: Invalid validity window number: '%s'\n", line_num, val );
				}
			}

			int window = atoi( val );
			if ( window > MAX_VALIDITY_WINDOW || window < MIN_VALIDITY_WINDOW ) {
				write_error_log( "Config line #%d: Validity window of '%d' is out of the range:  10 < x < 86400\n", line_num, window );
			}

			spa_conf.validity_window = window;
			__debuglog( write_log( "+++++ Validity window for SPA timestamps set to '%d'\n", window ); )
		}

		// Get whether replays are being prevented.
		else if ( strcmp( key, "prevent_replay" ) == 0 ) {
			int state = is_bool_option_yes( val );
			set_config_flag( (state == EXIT_SUCCESS ? ON : OFF), SPA_CONF_FLAG_PREVENT_REPLAY );
			__debuglog( write_log( "+++++ Prevent Replay feature is '%s'.\n", (state == EXIT_SUCCESS ? "on" : "off") ); )
		}

		// Get whether invalid pubkeys should be skipped. This should be defined BEFORE pubkeys if enabled.
		else if ( strcmp( key, "skip_invalid_pubkeys" ) == 0 ) {
			int state = is_bool_option_yes( val );
			set_config_flag( (state == EXIT_SUCCESS ? ON : OFF), SPA_CONF_FLAG_SKIP_INVALID_PKEY );
			__debuglog( write_log( "+++++ Skip Invalid Public Keys feature is '%s'.\n", (state == EXIT_SUCCESS ? "on" : "off") ); )
		}

		// Get the generic_action, if defined, and set its flag. The ID of the generic action is meaningless.
		else if ( strcmp( key, "generic_action" ) == 0 ) {
			if ( spa_conf.generic_action.action_id != 0 ||
				get_config_flag( SPA_CONF_FLAG_GENERIC_ACTION ) == EXIT_SUCCESS ) {
					write_error_log( "Config line #%d: The generic_action handler can only be specified one time.\n", line_num );
			} else if ( strnlen( val, MAX_ACTION_CMD_LEN ) > MAX_ACTION_CMD_LEN-1 ) {
				write_error_log( "Config line #%d: The generic_action handler command length cannot be greater than"
					" %d characters. Consider simplifying your handler.\n", line_num, MAX_ACTION_CMD_LEN-1 );
			}

			// Checks done. Load the action information into the meta config.
			malloc_sizeof( ACTION, p_action );

			p_action->action_id = (uint16_t)(ON & 0xFFFF);
			memcpy( &p_action->command[0], val, strlen(val)+1 );
			memcpy( &spa_conf.generic_action, p_action, sizeof(ACTION) );

			free( p_action );

			set_config_flag( ON, SPA_CONF_FLAG_GENERIC_ACTION );
			__debuglog( write_log( "+++++ Enabled generic action with command sequence: '%s'\n", val ); )

			write_syslog( LOG_WARNING, "WARNING: The generic_action handler is enabled. Actions and Autl policies"
				" will be disregarded, even if they were initially loaded!\n", NULL );
		}

		// Parse the list of users.
		else if ( strcmp( key, "users" ) == 0 ) {
			const char users_separator[2] = { ',', '\0' };
			char* username = strtok( val, users_separator );
			while ( username != NULL ) {
				strtolower( username );   // always set username to lower-case

				if ( get_user( (BYTE*)username ) != NULL ) {
					write_error_log( "The user '%s' is already defined.\n", username );
				}

				USER* p_new_user = create_user( (BYTE*)username );
				if ( p_new_user == NULL ) {
					write_error_log( "There was a problem creating the user '%s'.\n", username );
				}

				p_new_user->valid_user = ON;   // assume the user will be valid by default
				// ^ the autl/pubkey/etc functions will do the work to mark a user as invalid (0x00) as needed
				__debuglog( write_log( "+++++ Created user with name '%s'.\n", username ); )

				// Rotate to the next username.
				username = strtok( NULL, users_separator );
			}

			if ( get_user_count() <= 0 ) {
				write_error_log( "No valid usernames were loaded.\n", NULL );
			}

			__debuglog( write_log( "+++++ Loaded %d TOTAL users.\n", get_user_count() ); )
		}

		// Parse autls (requires 'users' to have been defined)
		else if ( strcmp( keyleft, "autl" ) == 0 ) {
			if ( get_user_count() <= 0 ) {
				write_error_log( "Config line #%d: The 'users' option must be defined BEFORE any autl entries.\n", line_num );
			} else if ( get_config_flag( SPA_CONF_FLAG_GENERIC_ACTION ) == EXIT_SUCCESS ) {
				write_syslog( LOG_WARNING, "WARNING: Not loading autl on line #%d because generic_action is set!\n", line_num );
				goto repeat_loop_cont;
			}

			USER* p_user = get_config_for_user( (BYTE*)keyright );
			if ( p_user == NULL ) {
				write_error_log( "Config line #%d: policy user could not be loaded. Is this user defined?", line_num );
			}

			__debuglog( write_log( "+++ Loading authorizations for '%s'.\n", p_user->username ); )
			load_user_autls( p_user, val );

			__debuglog( write_log( "+++++ User has total of %d authorization lists.\n", list_get_count( p_user->autl ) ); )
			free( p_user );
		}

		// Parse pubkeys (requires 'users' to have been defined)
		else if ( strcmp( keyleft, "pubkey" ) == 0 ) {
			if ( get_user_count() <= 0 ) {
				write_error_log( "Config line #%d: The 'users' option must be defined BEFORE any pubkey entries.\n", line_num );
			}

			USER* p_user = get_config_for_user( (BYTE*)keyright );
			if ( p_user == NULL ) {
				if ( get_config_flag( SPA_CONF_FLAG_SKIP_INVALID_PKEY ) != EXIT_SUCCESS ) {
					write_error_log( "Config line %d: pubkey user could not be loaded. Is this user defined?", line_num );
				} else {
					write_syslog( LOG_WARNING, "WARNING: Config line %d: pubkey user could not be loaded. Skipping...\n", line_num );
					free( p_user );
					goto repeat_loop_cont;
				}
			}
			if ( strnlen( (const char*)&p_user->pkey.key_path[0], PATH_MAX ) > 0 ) {
				if ( get_config_flag( SPA_CONF_FLAG_SKIP_INVALID_PKEY ) != EXIT_SUCCESS ) {
					write_error_log( "Config line %d: user '%s' already has a pubkey defined.", line_num, p_user->username );
				} else {
					write_syslog( LOG_WARNING, "WARNING: Config line %d: user '%s' already has a pubkey defined. Skipping...\n", line_num, p_user->username );
					free( p_user );
					goto repeat_loop_cont;
				}
			}

			if ( load_user_pkey( p_user, (BYTE*)val ) != EXIT_SUCCESS ) {
				if ( get_config_flag( SPA_CONF_FLAG_SKIP_INVALID_PKEY ) != EXIT_SUCCESS ) {
					write_error_log( "Config line %d: could not load pubkey '%s' for user '%s'.", line_num, val, p_user->username );
				} else {
					write_syslog( LOG_WARNING, "WARNING: Config line %d: could not load pubkey '%s' for user '%s'.\n", line_num, val, p_user->username );
					free( p_user );
					goto repeat_loop_cont;
				}
			}

			__debuglog( write_log( "+++++ Loaded pubkey for user '%s'.\n", p_user->username ); )
			free( p_user );
		}

		// Parse actions (requires the generic_action flag to have NOT been set; won't crash, just warn if it is)
		else if ( strcmp( keyleft, "action" ) == 0 ) {
			if ( get_config_flag( SPA_CONF_FLAG_GENERIC_ACTION ) == EXIT_SUCCESS ) {
				write_syslog( LOG_WARNING, "WARNING: Not loading action on line #%d because generic_action is set!\n", line_num );
				goto repeat_loop_cont;
			} else if ( strnlen( val, MAX_ACTION_CMD_LEN+1 ) > MAX_ACTION_CMD_LEN ) {
				write_error_log( "Config line #%d: Action command length is longer than the limit of %d characters.\n", line_num, MAX_ACTION_CMD_LEN-1 );
			}
			val[MAX_ACTION_CMD_LEN-1] = '\0';   //enforce null-term

			for ( int i = 0; i < strnlen(keyright,5); i++ ) {
				if ( !isdigit( keyright[i] ) ) {
					write_error_log( "Config line #%d: Action ID '%s' is not a valid number.\n", line_num, keyright );
				}
			}

			uint16_t action_id = (uint16_t)(atoi( keyright ) & 0xFFFF);
			if ( action_id < 1 || action_id >= UINT16_MAX ) {
				write_error_log( "Config line #%d: The provided action ID '%d' is out of the valid range.\n", line_num, action_id );
			}

			// Make sure we're not over the actions limit, and the action_id is unique.
			if ( get_actions_count() >= MAX_ACTIONS ) {
				write_error_log( "Config line #%d: Defined actions count exceeds limit of %d actions.", line_num, MAX_ACTIONS );
			}

			// Make sure this isn't a duplicate action.
			if ( get_action_by_id( &action_id ) != NULL ) {
				write_error_log( "Config line #%d: Action with ID '%d' is already defined.", line_num, action_id );
			}

			if ( create_action( &action_id, (BYTE*)val ) == NULL ) {
				write_error_log( "Config line #%d: Unspecified error creating action with ID '%d'.\n", line_num, action_id );
			}

			// Success.
			__debuglog( write_log( "+++++ Loaded action with ID '%d'.\n", action_id ); )
		}

		else if ( strcmp( keyleft, "sanitize_packet_data" ) == 0 ) {
			if ( keyright[0] == '\0' || val[0] == '\0' ) {
				write_error_log( "Config line %d: Sanitization cannot translate null (0x00) characters.\n", line_num );
			}

			__debuglog( write_log( "+++ Attempting to add packet_data sanitization for char '%c'.\n", keyright[0] ); )
			if ( spa_char_subs.count >= SPA_MAX_ACTION_SUBSTITUTIONS ) {
				write_error_log( "Config line %d: The amount of sanitization definitions"
					" exceeds the limit of %d.\n", SPA_MAX_ACTION_SUBSTITUTIONS );
			}

			__debuglog( write_log( "+++++ Adding new dynamic expansion structure to static list.\n", NULL ); )
			malloc_sizeof( struct spa_packet_data_replacement_t, p_repl );
			p_repl->before = (BYTE)keyright[0];
			p_repl->after = (BYTE)val[0];

			__debuglog( write_log( "+++++++ Before: '%c', After: '%c'\n", (char)p_repl->before, (char)p_repl->after ); )
			memcpy( &spa_char_subs.list[spa_char_subs.count], p_repl, sizeof(struct spa_packet_data_replacement_t) );
			spa_char_subs.count++;

			free( p_repl );
		}

		else if ( strcmp( keyleft, "ipv4_only" ) == 0 ) {
			int state = is_bool_option_yes( val );
			set_config_flag( (state == EXIT_SUCCESS ? ON : OFF), SPA_CONF_FLAG_IPV4_ONLY );
			__debuglog( write_log( "+++++ IPv4-only feature is '%s'.\n", (state == EXIT_SUCCESS ? "on" : "off") ); )
		}

		else if ( strcmp( keyleft, "ipv6_only" ) == 0 ) {
			int state = is_bool_option_yes( val );
			set_config_flag( (state == EXIT_SUCCESS ? ON : OFF), SPA_CONF_FLAG_IPV6_ONLY );
			__debuglog( write_log( "+++++ IPv6-only feature is '%s'.\n", (state == EXIT_SUCCESS ? "on" : "off") ); )
		}

		else if ( strcmp( keyleft, "bind_interface" ) == 0 ) {
			if ( strnlen( (const char*)&spa_conf.bind_interface[0], IF_NAMESIZE ) != 0 ) {
				write_error_log( "Config line %d: The bind interface can only be specified once.\n", line_num );
			} else if ( strnlen( (const char*)&spa_conf.bind_interface[0], IF_NAMESIZE+1 ) > IF_NAMESIZE ) {
				write_error_log( "Config line %d: Interface name exceeds max size of %d characters.\n", line_num, IF_NAMESIZE-1 );
			}

			memcpy( &spa_conf.bind_interface[0], val, strnlen(val,IF_NAMESIZE) );
			spa_conf.bind_interface[IF_NAMESIZE-1] = '\0';   //force null-term
		}

		else if ( strcmp( keyleft, "bind_address" ) == 0 ) {
			if ( strnlen( (const char*)&spa_conf.bind_address[0], INET6_ADDRSTRLEN ) != 0 ) {
				write_error_log( "Config line %d: The bind address can only be specified once.\n", line_num );
			} else if ( strnlen( (const char*)&spa_conf.bind_address[0], INET6_ADDRSTRLEN+1 ) > INET6_ADDRSTRLEN ) {
				write_error_log( "Config line %d: Bind address exceeds max size of %d characters.\n", line_num, INET6_ADDRSTRLEN-1 );
			}

			memcpy( &spa_conf.bind_address[0], val, strnlen(val,INET6_ADDRSTRLEN) );
			spa_conf.bind_address[INET6_ADDRSTRLEN-1] = '\0';   //force null-term
		}

		else if ( strcmp( keyleft, "i_agree" ) == 0 ) {
			int state = is_bool_option_yes( val );
			set_config_flag( (state == EXIT_SUCCESS ? ON : OFF), SPA_CONF_FLAG_ACCEPT_TERMS );
			__debuglog( write_log( "+++++ Configuration/Terms agreement is '%s'.\n", (state == EXIT_SUCCESS ? "on" : "off") ); )
		}

		else if ( strcmp( keyleft, "map_ipv4_addresses" ) == 0 ) {
			int state = is_bool_option_yes( val );
			// Reversed thanks to double-negative language..
			set_config_flag( (state == EXIT_SUCCESS ? OFF : ON), SPA_CONF_FLAG_NO_IPV4_MAPPING );
			__debuglog( write_log( "+++++ IPv4-to-IPv6 address mapping (map_ipv4_addresses)"
				" for SRCIP tokens is '%s'.\n", (state == EXIT_SUCCESS ? "on" : "off") ); )
		}

		// Any other key in the configuration file should get the attention of the end user.
		else {
			write_error_log( "Config line #%d: Unrecognized configuration key '%s'."
				" Remove this value or comment it.\n\n", line_num, key );
		}

		repeat_loop_cont:
			free( keyx );
			__debuglog( printf( "\n" ); )  //pretty for the terminal when run by CLI
	}

	set_config_flag( ON, SPA_CONF_FLAG_LOAD_SUCCESS );
	fclose( config_file_h );
	return check_config();
}
