/*
 * CSPAuthD main server application.
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


#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <time.h>
#include <err.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <getopt.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <syslog.h>
#include <linux/limits.h>

#include "../spa.h"
#include "../integrity.h"
#include "log.h"
#include "conf.h"
#include "users.h"
#include "replay.h"
#include "verify.h"



// Global variables.
static char* p_default_conf = "/etc/cspauthd.conf";
static int mainsockfd = -1;
static sa_family_t listen_family = -1;



// Functions to define later.
uint64_t generate_packet_id();
void* handle_packet( void* packet );
int send_response( uint64_t* packet_id, struct sockaddr_in6* p_clientaddr,
    uint16_t response_code, char* response_msg );
void spawn_socket();
void register_signals();
void handle_signal( int signal );
void syslog_init();
void daemonize();



int main( int argc, char **argv ) {
    // Even with debugging on, it doesn't really seem useful to log anything before the config loading steps.
    //   ...
    memset( &spa_process, 0, sizeof(struct spa_process_meta_t) );

    // Register signals handling and initialize the global configuration object.
    register_signals();
    clear_config();


    // Other initializations.
    openssl_init();

    char* syslog_tag = (char*)"cspauthd";
    memcpy( &spa_process.syslog_tag[0], syslog_tag,
        strnlen((const char*)syslog_tag,SPA_CONF_SYSLOG_TAG_MAX_STRLEN) );
    syslog_init();


    // Ensure the 'system' command has a shall available. Otherwise, the entire application is pointless.
    if ( system(NULL) == 0 ) {
        char p_username[32];
        memset( &p_username[0], 0, 32 );
        getlogin_r( &p_username[0], 32 );
        if ( strnlen( p_username, 32 ) != 0 ) {
            errx( 1, "No shell appears to be available for the executing user '%s'. Terminating.\n", p_username );
        } else {
            errx( 1, "No shell appears to be available for the executing user. Terminating.\n" );
        }
    }


    // Get passed CLI options.
    struct option cli_long_options[] = {
        { "help",        no_argument,        NULL,    'h' },
        { "debug",        no_argument,        NULL,    'x' },
        { "daemon",        no_argument,        NULL,    'd' },
        { "pidfile",    required_argument,    NULL,    'p' },
        { "configfile",    required_argument,    NULL,    'c' },
        { 0,            0,                    0,        0 }
    };
    int cli_option_index = 0;
    int cli_opt;
    char conf_file_c[PATH_MAX];
    char* conf_file = &conf_file_c[0];
    char pid_file_c[PATH_MAX];
    char* pid_file = &pid_file_c[0];
    memset( conf_file_c, 0, PATH_MAX );
    memset( pid_file_c, 0, PATH_MAX );


    // Parse CLI args.
    for ( ; ; ) {
        cli_opt = getopt_long( argc, argv, "hxdp:c:", cli_long_options, &cli_option_index );
        if ( cli_opt == -1 )  break;
        switch ( cli_opt ) {
            default :
            case 'h':
                printf( "This is a placeholder for the application's help/usage information.\n\n" );
                exit( 0 );
            case 'x':
                spa_process.debug_mode = ON;
                break;
            case 'd':
                spa_process.daemonized = ON;
                break;
            case 'p':
                // The PID file will be disregarded if the application is not daemonized.
                if ( (pid_file = (char*)strndup(optarg,PATH_MAX)) == NULL )
                    errx( 1, "strndup: failed to set pid-file override parameter.\n" );
                memcpy( &spa_process.pidfile_path, pid_file, strnlen((const char*)pid_file,PATH_MAX) );
                break;
            case 'c':
                if ( (conf_file = (char*)strndup(optarg,PATH_MAX)) == NULL )
                    errx( 1, "strndup: failed to set config-file override parameter.\n" );
                break;
        }
    }


    // Load the service configuration.
    if ( strnlen( (const char*)conf_file, PATH_MAX ) <= 0 )
        conf_file = p_default_conf;

    // Start logging here based on target log-level.
    //   The program assumes DEBUG logging until the log_level conf is loaded.
    parse_config( conf_file );
    memcpy( &spa_process.config_path[0], conf_file, strnlen((const char*)conf_file,PATH_MAX) );
    conf_file = NULL;

    __debuglog( write_log( "Checking conf flags register for config load success.\n", NULL ); )
    if ( IS_CONFIG_LOADED ) {
        write_log( "===== CSPAuthD configuration loaded successfully! =====\n", NULL );
    } else {
        write_error_log( "CSPAuthD configuration wasn't loaded successfully. Exiting.\n", NULL );
    }


    // If daemonization was requested, do that now before listening.
    __debuglog( write_log( "Checking daemonization request.\n", NULL ); )
    if ( IS_DAEMONIZED )  daemonize();


    // Create the monitoring thread for keeping track of replays.
    __debuglog( write_log( "Initializing replay monitor thread.\n", NULL ); )
    if ( prevent_replay_init() != EXIT_SUCCESS ) {
        write_error_log( "Failed to create the replay monitor thread. Exiting.\n", NULL );
    }


    // Begin the listening process based on the configuration parameters.
    spawn_socket();


    // Enter the primary application loop. This continues until stopped by a signal.
    //   Each connection received spins off a handler thread, so the socket is non-blocking.
    //   TODO: implement a maximum thread count?
    __debuglog( write_log( "Entering main program iteration loop.\n", NULL ); )
    size_t nbytes;
    char recv_buffer[PACKET_BUFFER_SIZE];
    char send_buffer[PACKET_BUFFER_SIZE];
    struct sockaddr_in6 clientaddr;
    while ( 1 ) {
        __debuglog( write_log( "Clearing send/recv buffers with memory size %d.\n", PACKET_BUFFER_SIZE ); )

        memset( &nbytes, 0, sizeof(size_t) );
        memset( &recv_buffer[0], 0, PACKET_BUFFER_SIZE );
        memset( &send_buffer[0], 0, PACKET_BUFFER_SIZE );
        memset( &clientaddr, 0, sizeof(struct sockaddr_in6) );

        __verboselog( write_log( "Main thread: Waiting for new data.\n", NULL ); )
        if ( listen_family == AF_INET6 ) {
            int clientaddrlen = sizeof(struct sockaddr_in6);
            if ( (nbytes = recvfrom( mainsockfd, recv_buffer, PACKET_BUFFER_SIZE,
                    MSG_WAITALL, (struct sockaddr*)&clientaddr, (socklen_t*)&clientaddrlen )) < 0 ) {
                write_error_log_append( "recv", NULL );
            }
        } else {
            int clientaddrlen = sizeof(struct sockaddr_in);
            malloc_sizeof( struct sockaddr_in, p_sin4 );
            if ( (nbytes = recvfrom( mainsockfd, recv_buffer, PACKET_BUFFER_SIZE,
                    MSG_WAITALL, (struct sockaddr*)p_sin4, (socklen_t*)&clientaddrlen )) < 0 ) {
                write_error_log_append( "recv", NULL );
            }

            // Convert the v4 socket to v6 so it can be used universally.
            //   It gets converted back later as needed.
            malloc_sizeof( struct sockaddr_in6, p_sin6 );
            p_sin6->sin6_family = AF_INET6;
            p_sin6->sin6_port = p_sin4->sin_port;
            p_sin6->sin6_addr.s6_addr[10] = 0xFF;
            p_sin6->sin6_addr.s6_addr[11] = 0xFF;
            memcpy( &p_sin6->sin6_addr.s6_addr[12], &p_sin4->sin_addr, sizeof(char)*4 );

            memcpy( &clientaddr, p_sin6, sizeof(struct sockaddr_in6) );
            free( p_sin6 );
            free( p_sin4 );
        }
        // Usually ridiculous numbers from the socket indicate a signal was trapped.
        //   In such events, the main thread should just quietly continue to run.
        if ( nbytes < 0 || nbytes > UINT64_MAX-1 ) {
            __debuglog( write_log( "Received 0 or > uint64_t size packet -- '%lu' bytes "
                "-- usually a SIGHUP on the socket.\n", nbytes ); )
            continue;
        }

        __verboselog(
            char client_addr[INET6_ADDRSTRLEN];
            memset( &client_addr[0], 0, INET6_ADDRSTRLEN );
            inet_ntop( AF_INET6, &(clientaddr.sin6_addr), client_addr, INET6_ADDRSTRLEN );
            write_log( "Received %lu bytes of UDP socket data from '%s' on port '%d'.\n", nbytes, client_addr, clientaddr.sin6_port );
        )

        if ( nbytes < SPA_PACKET_MIN_SIZE || nbytes > SPA_PACKET_MAX_SIZE ) {
            __verboselog( write_log( "Invalid SPA packet length. Expected between %lu and"
                " %lu bytes of data.\n", SPA_PACKET_MIN_SIZE, SPA_PACKET_MAX_SIZE ); )
            continue;
        } else if ( pre_packet_verify( &recv_buffer[0] ) != EXIT_SUCCESS ) {
            __verboselog( write_log( "Detected an invalid UDP packet format. Discarding data.\n", NULL ); )
            continue;
        }

        // Receive and parse the packet; fill in the meta information to pass to the thread.
        __debuglog( write_log( "Generating packet meta-structure for thread.\n", NULL ); )
        //struct spa_packet_meta_t* spa_meta = malloc( sizeof(struct spa_packet_meta_t) );
        malloc_sizeof( struct spa_packet_meta_t, spa_meta );
        memset( spa_meta, 0, sizeof(struct spa_packet_meta_t) );
        memcpy( &spa_meta->clientaddr, &clientaddr, sizeof(struct sockaddr_in6) );
        memcpy( &spa_meta->packet, recv_buffer, sizeof(struct spa_packet_t) );
        __debuglog( write_log( "Generating packet ID.\n", NULL ); )
        spa_meta->packet_id = generate_packet_id();
        __debuglog( write_log( "Got packet ID tag: |%lu|\n", spa_meta->packet_id ); )

        // Spin off a detached thread to handle the SPA.
        __debuglog ( packet_log( spa_meta->packet_id, "Creating detached pthread for SPA packet event.\n", NULL ); )
        pthread_attr_t tattr;
        pthread_attr_init( &tattr );
        pthread_attr_setdetachstate( &tattr, 1 );
        pthread_t t;
        int rc = pthread_create( &t, &tattr, handle_packet, spa_meta );
        pthread_attr_destroy( &tattr );
        __debuglog( write_log( "Post-spawn (thread afterbirth) cleanup.\n", NULL ); )
        if ( rc != 0 ) {
            __debuglog( write_log( "Problem using pthread_create to create detached packet handling thread.\n", NULL ); )
            free( spa_meta );
        }
    }

    __debuglog( write_log( "Application broke from main thread iteration. Exiting.\n", NULL ); )
    return 0;
}



void* handle_packet( void* p_packet_meta ) {
        // Get some information from the packet meta details after casting, then free the pointer parameter.
        malloc_sizeof( struct spa_packet_meta_t, p_meta_packet );
        memset( p_meta_packet, 0, sizeof(struct spa_packet_meta_t) );
        memcpy( p_meta_packet, p_packet_meta, sizeof(struct spa_packet_meta_t) );
        free( p_packet_meta );


        // Make sure the conf is not actively being reloaded or is having an issue.
        if ( !(IS_CONFIG_LOADED) ) {
            free( p_meta_packet );
            __quietlog( write_syslog( LOG_WARNING, "WARNING: Unable to process incoming"
                " packet while configuration unloaded!\n", NULL ); )
            return NULL;
        }


        // Set up shorthand references to packet details.
        struct spa_packet_t* auth_packet = &p_meta_packet->packet;
        struct sockaddr_in6* clientaddr = &p_meta_packet->clientaddr;
        uint64_t* packet_id = &p_meta_packet->packet_id;

        char client_addr[INET6_ADDRSTRLEN];
        memset( &client_addr[0], 0, INET6_ADDRSTRLEN );
        inet_ntop( AF_INET6, &clientaddr->sin6_addr, client_addr, INET6_ADDRSTRLEN );

        __normallog(
            packet_log( *packet_id, "Received SPA packet from '%s', port '%d'.\n", client_addr, clientaddr->sin6_port );
        )


        // Get string-like fields and forcibly null-terminate them.
        char username[SPA_PACKET_USERNAME_SIZE+1];
        memset( username, 0, SPA_PACKET_USERNAME_SIZE+1 );
        memcpy( username, &auth_packet->username, SPA_PACKET_USERNAME_SIZE );
        username[SPA_PACKET_USERNAME_SIZE] = '\0';

        // This is not necessary to null-term; it's not a string.
        char signature[SPA_PACKET_HASH_SIZE];
        memset( signature, 0, SPA_PACKET_HASH_SIZE );
        memcpy( signature, &auth_packet->packet_hash, SPA_PACKET_HASH_SIZE );


        __verboselog(
            char sigtohex[(SPA_PACKET_HASH_SIZE*2) + 1];
            memset( sigtohex, 0, (SPA_PACKET_HASH_SIZE*2)+1 );
            for ( int i = 0; i < SPA_PACKET_HASH_SIZE; i++ )  snprintf( &sigtohex[i*2], 3, "%02x", (unsigned int)auth_packet->packet_hash[i] );
            sigtohex[SPA_PACKET_HASH_SIZE*2] = '\0';

            packet_log( *packet_id, "+++ Username: %s\n", username );
            packet_log( *packet_id, "+++ Timestamp: %lu\n", auth_packet->client_timestamp );
            packet_log( *packet_id, "+++ Requested ACT_OPT: %d_%d\n", auth_packet->request_action, auth_packet->request_option );
            packet_log( *packet_id, "+++ Hash (sha256): %s\n", sigtohex );
#ifdef DEBUG
            fprintf( stderr, "Hexdumping packet signature:\n" );
            __debuglog( print_hex( auth_packet->packet_hash, SPA_PACKET_HASH_SIZE ); )
#endif
        )


        /* Process for authenticating and authorizing an incoming SPA packet:
         *   1 - Check the timestamp. Is the time within the configured validity window according to the server time?
         *   2 - Validate the username. Make sure they exist and are not marked invalid.
         *      2.5 - Get the user's loaded configuration settings.
         *   3 - Hash the packet locally and make sure it matches the packet hash.
         *      3.5 - Make sure this isn't a replayed packet.
         *   4 - Check whether the requested action is loaded in the running configuration.
         *   5 - See if the user is authorized to perform the action.
         *   6 - See if the user has a valid and loaded public key.
         *   7 - Authenticate the signature on the packet using the public key.
         *      7.5 - Record the packet hash, if desired.
         *   8 - Authorize and perform the requested action.
         *   9 - Depending on the mode, issue a response packet to the client:port.
         */

        if ( verify_timestamp( packet_id, &auth_packet->client_timestamp ) != EXIT_SUCCESS ) {
            __normallog( packet_syslog( *packet_id, LOG_NOTICE, "Inbound packet failed timestamp verification.\n", NULL ); )
            send_response( packet_id, clientaddr, SPA_CODE_BAD_TIMESTAMP, (char*)"Invalid timestamp" );
            goto handle_packet_cleanup_a;
        }

        // NOTE: always free this resource during thread cleanup!
        USER* p_user_data = get_config_for_user( username );
        if ( p_user_data == NULL || verify_username( packet_id, username ) != EXIT_SUCCESS ) {
            __normallog( packet_syslog( *packet_id, LOG_NOTICE, "Could not fetch configuration settings for user '%s'.\n", username ); )
            send_response( packet_id, clientaddr, SPA_CODE_INVALID_USER, (char*)"Invalid or illegal user" );
            goto handle_packet_cleanup_b;
        }

        if ( verify_packet_hash( packet_id, auth_packet ) != EXIT_SUCCESS ) {
            __normallog( packet_syslog( *packet_id, LOG_NOTICE, "Packet sha256 hash mismatch.\n", NULL ); )
            send_response( packet_id, clientaddr, SPA_CODE_HASH_MISMATCH, (char*)"sha256 mismatch" );
            goto handle_packet_cleanup_b;
        }

        if ( SPAConf__get_flag( SPA_CONF_FLAG_PREVENT_REPLAY ) == EXIT_SUCCESS ) {
            __verboselog( packet_log( *packet_id, "+++ Checking packet hash for replays.\n", NULL ); )
            if ( check_for_replay( &auth_packet->packet_hash[0] ) != EXIT_SUCCESS ) {
                __normallog( packet_syslog( *packet_id, LOG_NOTICE, "Packet replay detected. Same hash within last '%d' seconds.\n", spa_conf.validity_window ); )
                send_response( packet_id, clientaddr, SPA_CODE_REPLAYED, (char*)"Replay detected" );
                goto handle_packet_cleanup_b;
            }
        }

        // NOTE: always free this resource during thread cleanup!
        malloc_sizeof( ACTION, p_spa_action );
        if ( verify_action( packet_id, p_spa_action, &auth_packet->request_action ) != EXIT_SUCCESS ) {
            __normallog( packet_syslog( *packet_id, LOG_NOTICE, "Action ID '%d' is not a loaded or valid action.\n", auth_packet->request_action ); )
            // Issue a response, depending on the program MODE setting.
            send_response( packet_id, clientaddr, SPA_CODE_INVALID_ACTION, (char*)"Invalid action ID" );
            goto handle_packet_cleanup_c;
        }

        if ( verify_pubkey( packet_id, p_user_data ) != EXIT_SUCCESS ) {
            __normallog( packet_syslog( *packet_id, LOG_NOTICE, "User '%s' does not have a valid public key.\n", username ); )
            // Issue a response, depending on the program MODE setting.
            send_response( packet_id, clientaddr, SPA_CODE_INVALID_PKEY, (char*)"Invalid user public key" );
            goto handle_packet_cleanup_c;
        }

        if ( verify_signature( packet_id, auth_packet, p_user_data ) != EXIT_SUCCESS ) {
            __normallog( packet_syslog( *packet_id, LOG_NOTICE, "Packet crypto signature failed to verify.\n", NULL ); )
            // Issue a response, depending on the program MODE setting.
            send_response( packet_id, clientaddr, SPA_CODE_INVALID_SIGNATURE, (char*)"Crypto signature invalid" );
            goto handle_packet_cleanup_c;
        }

        if ( verify_authorization( packet_id, p_user_data, &auth_packet->request_action, &auth_packet->request_option ) != EXIT_SUCCESS ) {
            __normallog(
                packet_syslog( *packet_id, LOG_NOTICE, "User '%s' is not authorized to perform action '%d' with option '%d'.\n",
                    username, auth_packet->request_action, auth_packet->request_option );
            )
            // Issue a response, depending on the program MODE setting.
            send_response( packet_id, clientaddr, SPA_CODE_NOT_AUTHORIZED, (char*)"User is not authorized" );
            goto handle_packet_cleanup_c;
        }


        // If applicable, record the packet signature so it cannot be used again.
        if ( SPAConf__get_flag( SPA_CONF_FLAG_PREVENT_REPLAY ) == EXIT_SUCCESS ) {
            __verboselog( packet_log( *packet_id, "+++ Recording packet hash into the time-based linked list.\n", NULL ); )
            create_replay_record( &auth_packet->packet_hash[0], &auth_packet->client_timestamp );
        }


        // Issue a response, depending on the program MODE setting.
        //   This should be done _before_ performing the action, since an authorized function may have a delay involved.
        if ( send_response( packet_id, clientaddr, SPA_CODE_SUCCESS,
                (char*)"Successful action authorization" ) != EXIT_SUCCESS ) {
            goto handle_packet_cleanup_c;
        }


        // Actually perform the action as requested. This will take care of all string expansions as needed.
        __quietlog(
            packet_syslog(
                *packet_id, LOG_NOTICE,
                "Processing authorized SPA packet from '%s', user '%s', function %d:%d\n",
                client_addr, username, auth_packet->request_action, auth_packet->request_option
            );
        )
        if ( perform_action( p_spa_action, p_meta_packet, &listen_family ) != EXIT_SUCCESS ) {
            __normallog( packet_syslog( *packet_id, LOG_NOTICE, "Failed to perform the authorized function request.\n", NULL ); )
            goto handle_packet_cleanup_c;
        } else {
            __quietlog(
                packet_syslog( *packet_id, LOG_NOTICE,
                    "Authorized function performed successfully. Cleaning up.\n",
                    client_addr, auth_packet->request_action, auth_packet->request_option );
            )
        }


        // End the thread.
        __debuglog( packet_log( *packet_id, "Finished thread processing successfully with no code jumps.\n", NULL ); )
    handle_packet_cleanup_c:
        free( p_spa_action );
    handle_packet_cleanup_b:
        free( p_user_data );
    handle_packet_cleanup_a:
        free( p_meta_packet );
        __debuglog( write_log( "Ending thread.\n", NULL ); )
        return NULL;
}



uint64_t generate_packet_id() {
    uint64_t r = 0;

    for ( int i = 0; i< 64; i+= RAND_MAX_WIDTH ) {
        r <<= RAND_MAX_WIDTH;
        r ^= (unsigned)rand();
    }

    return r;
}



int send_response( uint64_t* packet_id, struct sockaddr_in6* p_clientaddr,
    uint16_t response_code, char* response_msg ) {
/*
# Valid selections are:
#   dead: The service won't even respond to successful, authorized SPA packets. Completely silent.
#   stealthy: The service will never issue a response to an invalid SPA packet, but will
#     gladly respond to successful authorizations -- meaning an action was authorized by the SPA.
#   helpful: The service will never respond to invalid SPA packets, but will always respond to
#     successful authentications, even if the user is not authorized to perform the requested
#     action. In other words, only authentications will always generate a response, but if the
#     user isn't authorized for the requested action, responses will still be sent to notify them.
#   noisy: NOT RECOMMENDED. The service will respond to SPA packets, including ones that fail,
#     but if and only if the service parses what appears to be a valid SPA packet format.
*/

# ifdef DEBUG
__debuglog(
    write_log( "***** RESPOND_TO_CLIENT: Issuing response to client according" \
        " to mode: '%d'; '0x%08x': '%s' *****\n", spa_conf.mode, response_code, response_msg );
    //write_log( " ***** `---> Datagram to '%s'
)
# endif

    // Just don't do anything for 'dead' mode. It's completely silent, so it's ignored in this conditional.
    if ( spa_conf.mode == dead ) {
        __debuglog( packet_log( *packet_id, "Application running in 'dead' mode -- not issuing packet response.\n", NULL ); )
        return EXIT_SUCCESS;
    }


    // Create the response packet.
    malloc_sizeof( struct spa_response_packet_t, p_resp_packet );
    uint8_t msglen = (uint8_t)strnlen((const char*)response_msg,SPA_RESPONSE_STRLEN-1);

    p_resp_packet->server_version = SPA_SERVER_VERSION;

    p_resp_packet->response_code = response_code;

    p_resp_packet->reserved = 0x0000;

    time_t now;
    time( &now );
    uint64_t current_time = (uint64_t)now;
    p_resp_packet->timestamp = current_time;

    p_resp_packet->packet_id = *packet_id;

    memcpy( &p_resp_packet->response_data[0], response_msg, msglen );
    p_resp_packet->response_data[SPA_RESPONSE_STRLEN-1] = '\0';   //force null-term


    if ( spa_conf.mode == stealthy ) {
        // Responds only to successful SPA actions.
        if ( response_code != SPA_CODE_SUCCESS ) {
            __debuglog( packet_log( *packet_id, "Stealthy mode enabled and this packet wasn't valid. Staying quiet.\n", NULL ); )
            goto __send_response_success;
        }
    } else if ( spa_conf.mode == helpful ) {
        // Responds only to successful SPA actions and SPA packets which have a good signature but lack authorization.
        if ( response_code != SPA_CODE_SUCCESS && response_code != SPA_CODE_NOT_AUTHORIZED ) {
            __debuglog( packet_log( *packet_id, "Helpful mode enabled and this packet wasn't authorized or successful. Staying quiet.\n", NULL ); )
            goto __send_response_success;
        }
    } else if ( spa_conf.mode == noisy ) {
        // Needs a valid SPA packet format to send a response, whether the packet is successful or not.
    } else {
        __normallog(
            packet_syslog( *packet_id, LOG_WARNING, "WARNING: The application mode could"
                " not be determined. Got mode '%d'.\n", spa_conf.mode );
        )
        goto __send_response_failed;
    }

    // Now, actually send the populated response data.
# ifdef DEBUG
__debuglog( packet_log( *packet_id, "Sending response datagram with payload hexdump:\n", NULL ); )
print_hex( (char*)p_resp_packet, sizeof(struct spa_response_packet_t) );
# endif

    int sentbytes = -1;
    if ( listen_family == AF_INET ) {
        malloc_sizeof( struct sockaddr_in, p_ip4 );
        p_ip4->sin_family = AF_INET;
        p_ip4->sin_port = p_clientaddr->sin6_port;
        memcpy( &p_ip4->sin_addr, &p_clientaddr->sin6_addr.s6_addr[12], 4 );
# ifdef DEBUG
    __debuglog( printf( "=== Dumping sendto sockaddr_in:\n" ); )
    print_hex( (char*)p_ip4, sizeof(struct sockaddr_in) );
# endif
        sentbytes = sendto( mainsockfd, (char*)p_resp_packet,
            sizeof( struct spa_response_packet_t ),
            0, (struct sockaddr*)p_ip4, (socklen_t)sizeof(struct sockaddr_in) );
        free( p_ip4 );
    } else {
# ifdef DEBUG
    __debuglog( printf( "=== Dumping sendto sockaddr_in6:\n" ); )
    print_hex( (char*)p_clientaddr, sizeof(struct sockaddr_in6) );
# endif
        sentbytes = sendto( mainsockfd, (char*)p_resp_packet,
            sizeof( struct spa_response_packet_t ),
            0, (struct sockaddr*)p_clientaddr, (socklen_t)sizeof(struct sockaddr_in6) );
    }

    if ( sentbytes < 0 ) {
        __normallog(
            packet_syslog( *packet_id, LOG_WARNING, "WARNING: Attempted to send"
                " UDP response but failed to dispatch: %s\n", strerror(errno) );
        )
        goto __send_response_failed;
    }

    // Good exit.
    __send_response_success:
        free( p_resp_packet );
        return EXIT_SUCCESS;

    // Jump here on failure to send data for any reason.
    __send_response_failed:
        free( p_resp_packet );
        return EXIT_FAILURE;
}



void spawn_socket() {
    int sockfd;
    struct sockaddr_in6 sock6;
    memset( &sock6, 0, sizeof(struct sockaddr_in6) );

    if ( mainsockfd != -1 ) {
        if ( close(mainsockfd) < 0 ) {
            write_error_log_append( "socket-close", NULL );
        }
        mainsockfd = -1;
    }

    __debuglog( write_log( "Receiving socket file descriptor for UDP bind.\n", NULL ); )
    if ( (sockfd = socket(((IS_IPV4_ONLY) ? AF_INET : AF_INET6), SOCK_DGRAM, 0)) == -1 )
        write_error_log_append( "socket", NULL );

    mainsockfd = sockfd;
    __debuglog( write_log( "Got sockfd: %d.\n", sockfd ); )
    sock6.sin6_family = ((IS_IPV4_ONLY) ? AF_INET : AF_INET6);
    sock6.sin6_port = htons( (spa_conf.bind_port <= 0 ? SPA_DEFAULT_BIND_PORT : spa_conf.bind_port) );

    __debuglog( write_log( "Setting socket options.\n", NULL ); )
    char* p_if = &spa_conf.bind_interface[0];
    int is_any_interface = OFF;
    if ( strncmp( (const char*)p_if, "any", IF_NAMESIZE ) != 0 ) {
        __normallog( write_log( "* Binding to interface '%s'.\n", p_if ); )
        if (  ( setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, p_if, strnlen((const char*)p_if,IF_NAMESIZE)) ) < 0  )
            write_error_log_append( "setsockopt:BINDTODEVICE", NULL );
    } else {
        is_any_interface = ON;
        __normallog( write_log( "* Binding to any interface.\n", NULL ); )
    }
    int reuse_flag = 0;
    if (  ( setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, &reuse_flag, sizeof(int)) ) < 0  )
        write_error_log_append( "setsockopt:REUSEPORT", NULL );
    if (  ( setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse_flag, sizeof(int)) ) < 0  )
        write_error_log_append( "setsockopt:REUSEADDR", NULL );
    if ( IS_IPV6_ONLY ) {
        int set_on = 1;
        if (  ( setsockopt(sockfd, IPPROTO_IPV6, IPV6_V6ONLY, &set_on, sizeof(int)) ) < 0  )
            write_error_log_append( "setsockopt:IPV6_V6ONLY", NULL );
    }

    char* p_baddr = &spa_conf.bind_address[0];
    if ( strncmp( (const char*)p_baddr, "any", INET6_ADDRSTRLEN ) != 0 ) {
        __debuglog( write_log( "* Attempting to bind to address '%s'.\n", p_baddr ); )

        malloc_sizeof( struct ifaddrs, p_ifas );
        if ( getifaddrs( &p_ifas ) != 0 ) {
            write_error_log_append( "getifaddrs", NULL );
        } else if ( p_ifas == NULL ) {
            write_error_log( "Tried to get interface addresses but got NULL.\n", NULL );
        }

        // Interpret the given address for validity.
        int __baddrfam = AF_INET;
        for ( char* p = &p_baddr[0]; p < (p_baddr+INET6_ADDRSTRLEN); p++ ) {
            if ( *p == ':' )  __baddrfam = AF_INET6;
        }
        if ( __baddrfam != AF_INET && (IS_IPV4_ONLY) ) {
            write_error_log( "The given bind_address '%s' is not an IPv4 address, and"
                " the application is set to only use IPv4.\n", p_baddr );
        }

        void* __p_baddr = malloc( sizeof(struct in6_addr) );
        memset( __p_baddr, 0, sizeof(struct in6_addr) );
        int __interp_rc = inet_pton( __baddrfam, (const char*)p_baddr, __p_baddr );
        if (  __interp_rc != 1 ) {
            write_error_log( "The given bind_address '%s' is not a valid IPv%c address.\n",
                p_baddr, (__baddrfam == AF_INET ? '4' : '6') );
        }

        __debuglog( write_log( "*** Enumerating local interface addresses.\n", NULL ); )
        int is_baddr_found = OFF;
        struct ifaddrs* p_nextifa = p_ifas;
        do {
            if ( is_any_interface == OFF ) {
                // If the program binds to a specific interface, skip this interface if its name doesn't match.
                if ( strncmp( &p_nextifa->ifa_name[0], (const char*)p_if, IF_NAMESIZE ) != 0 )  continue;
            }
            // Skip non IPv4 or IPv6 family addresses.
            short int __addrfam = p_nextifa->ifa_addr->sa_family;
            if ( __addrfam != AF_INET && __addrfam != AF_INET6 )  continue;

            // Get the address based off the family.
            void* __the_addr = malloc( sizeof(struct in6_addr) );
            memset( __the_addr, 0, sizeof(struct in6_addr) );
            if ( __addrfam == AF_INET )
                memcpy( __the_addr, &(((struct sockaddr_in*)p_nextifa->ifa_addr)->sin_addr), sizeof(struct in_addr) );
            else
                memcpy( __the_addr, &(((struct sockaddr_in6*)p_nextifa->ifa_addr)->sin6_addr), sizeof(struct in6_addr) );

            // Make sure the IFADDR is a human-readble address, and output it if debug-mode.
            char ifaddr[INET6_ADDRSTRLEN];
            memset( &ifaddr[0], 0, INET6_ADDRSTRLEN );
            if ( inet_ntop( __addrfam, __the_addr, ifaddr, (__addrfam == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN) ) == NULL ) {
                free( __the_addr );
                continue;
            }
            __debuglog( write_log( "***** Discovered local address '%s', interface '%s'.\n", ifaddr, p_nextifa->ifa_name ); )

            // Now actually compare the addresses. If it matches, copy it in from the ptr and proceed.
            if ( memcmp( __p_baddr, __the_addr, (__addrfam == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr)) ) == 0 ) {
                __normallog( write_syslog( LOG_NOTICE, "* Using local bind address '%s', interface '%s'.\n", ifaddr, p_nextifa->ifa_name ); )
                memcpy( &(sock6.sin6_addr), __the_addr, (__addrfam == AF_INET ? sizeof(struct in_addr) : sizeof(struct in6_addr)) );
                free( __the_addr );
                is_baddr_found = ON;
                break;
            }

            free( __the_addr );
        } while ( (p_nextifa = p_nextifa->ifa_next) != NULL );

        free( __p_baddr );
        freeifaddrs( p_ifas );

        if ( is_baddr_found != ON ) {
            if ( is_any_interface == ON ) {
                write_error_log( "The bind_address '%s' was not found on the local system.\n", p_baddr );
            } else {
                write_error_log( "The bind_address '%s' is not an address on the interface '%s'.\n", p_baddr, p_if );
            }
        }
    } else {
        __normallog( write_log( "* Setting bind address to any.\n", NULL ); )
        sock6.sin6_addr = in6addr_any;
    }


    __debuglog( write_log( "Attempting to bind to port '%d' per service config.\n", spa_conf.bind_port ); )
    // This is quite a hacky way to just get a quick sockaddr_in from sock6, but it seems to work.
    int bindres = -1;
    if ( IS_IPV4_ONLY ) {
        malloc_sizeof( struct sockaddr_in, p_sock4 );
        p_sock4->sin_family = AF_INET;
        p_sock4->sin_port = sock6.sin6_port;
        memcpy( &(p_sock4->sin_addr), &(sock6.sin6_addr), sizeof(struct in_addr) );
        bindres = bind( sockfd, (struct sockaddr*)p_sock4, sizeof(struct sockaddr_in) );
        free( p_sock4 );
        listen_family = AF_INET;
    } else {
        bindres = bind( sockfd, (struct sockaddr*)&sock6, sizeof(struct sockaddr_in6) );
        listen_family = AF_INET6;
    }

    if ( bindres < 0 ) {
        write_error_log_append( "bind", NULL );
    }
    __normallog( write_log( "Ready to receive connections!\n", NULL ); )
}



void register_signals() {
    struct sigaction sa;
    memset( &sa, 0, sizeof(struct sigaction) );
    sa.sa_handler = handle_signal;
    sigaction( SIGINT,  &sa, NULL );
    sigaction( SIGTERM, &sa, NULL );
    sigaction( SIGKILL, &sa, NULL );
    sigaction( SIGHUP,  &sa, NULL );
    return;
}

void handle_signal( int signal ) {
    if ( signal == SIGHUP ) {
        write_syslog( LOG_WARNING, "Received signal SIGHUP. Reloading configuration...\n", NULL );

        __debuglog( write_log( "Reading process meta-info for configuration path.\n", NULL ); )
        char conf_path_c[PATH_MAX];
        char* conf_path = &conf_path_c[0];
        memset( conf_path, 0, PATH_MAX );
        memcpy( conf_path, &spa_process.config_path, strnlen((const char*)spa_process.config_path,PATH_MAX) );
        __debuglog( write_log( "Got conf path: |%s|\n", conf_path ); )

        clear_config();
        parse_config( conf_path );

        spawn_socket();   //rebind according to new conf params

        __normallog( write_log( "Config and socket reloaded. Ready to receive connections!\n", NULL ); )
    } else {
        write_syslog( LOG_WARNING, "Received signal '%d'. Goodbye.\n", signal );
        exit( 0 );
    }
}

void syslog_init() {
    openlog(
        (const char*)(&(spa_process.syslog_tag[0])),
        (LOG_CONS | LOG_NDELAY | LOG_PID),
        LOG_DAEMON
    );
    SPALog__write( LOG_NOTICE, "Initializing.\n", NULL );
}



void daemonize() {
    FILE* pidfile_h;
    pid_t pid;

    __debuglog( write_log( "Daemonizing.\n", NULL ); )
    __debuglog( write_log( "Checking pidfile at: |%s|\n", spa_process.pidfile_path ); )
    if ( strnlen((const char*)spa_process.pidfile_path,PATH_MAX) <= 0 )
        write_error_log( "Failed to daemonize: no PID file is defined with the '-p' option.\n", NULL );

    __debuglog( write_log( "First fork...\n", NULL ); )
    pid = fork();
    if ( pid < 0 )  write_error_log( "Failed to daemonize: first fork.\n", NULL );
    if ( pid > 0 )  exit( 0 );

    __debuglog( write_log( "setsid\n", NULL ); )
    if ( setsid() < 0 )    write_error_log_append( "setsid", NULL );
    __debuglog( write_log( "chdir to '/'\n", NULL ); )
    if ( chdir("/") < 0 )  write_error_log_append( "chdir", NULL );
    __debuglog( write_log( "umask(0);\n", NULL ); )
    umask( 0 );

    // Trash STDIN -- other handles can write out. Syslog/Jounal handles logging.
    __debuglog( write_log( "Redirecting STDIN to /dev/null\n", NULL ); )
    freopen( "/dev/null", "r", stdin );

    __debuglog( write_log( "Second fork...\n", NULL ); )
    pid = fork();
    if ( pid < 0 )  write_error_log( "Failed to daemonize: second fork.\n", NULL );
    if ( pid > 0 )  exit( 0 );

    __debuglog( write_log( "getpid\n", NULL ); )
    pid = getpid();
    __debuglog( write_log( "Received process ID: %d\n", pid ); )
    __debuglog( write_log( "fopen PID file handle for: |%s|\n", spa_process.pidfile_path ); )
    if ( (pidfile_h = fopen( (const char*)spa_process.pidfile_path, "w+" )) == NULL )
        write_error_log_append( "fopen", NULL );
    __debuglog( write_log( "Writing PID value to PID file.\n", NULL ); )
    if ( fprintf( pidfile_h, "%d", pid) < 0 )
        write_error_log( "Failed to write to PID file.\n", NULL );
    __debuglog( write_log( "fclose PID file handle.\n", NULL ); )
    if ( fclose( pidfile_h ) == EOF )
        write_error_log( "Failed to close the PID file handle.\n", NULL );
}
