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
#include <errno.h>
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
int send_response(
    uint64_t packet_id,
    struct sockaddr_in6* p_clientaddr,
    uint16_t response_code,
    char* response_msg
);
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
    SPAConf__clear();


    // Other initializations.
    openssl_init();
    SPAUser__init();
    SPAAction__init();

    char* syslog_tag = (char*)"cspauthd";
    memcpy( &spa_process.syslog_tag[0], syslog_tag,
        strnlen((const char*)syslog_tag,SPA_CONF_SYSLOG_TAG_MAX_STRLEN) );
    syslog_init();


    // Ensure the 'system' command has a shall available. Otherwise, the entire application is pointless.
    if (  0 == system( NULL )  ) {
        unsigned char p_username[32];
        memset( p_username, 0, 32 );

        getlogin_r( (char*)p_username, 32 );
        if (  0 != strnlen( (const char*)p_username, 32 )  ) {
            errx( 1, "No shell appears to be available for the executing "
                "user '%s'. Terminating.\n", p_username );
        } else {
            errx( 1, "No shell appears to be available for the executing "
                "user. Terminating.\n" );
        }
    }


    // Get passed CLI options.
    struct option cli_long_options[] = {
        { "help",       no_argument,        NULL,    'h' },
        { "debug",      no_argument,        NULL,    'x' },
        { "daemon",     no_argument,        NULL,    'd' },
        { "pidfile",    required_argument,  NULL,    'p' },
        { "configfile", required_argument,  NULL,    'c' },
        { 0,            0,                  0,        0  }
    };

    int cli_option_index = 0;
    int cli_opt;

    unsigned char conf_file_c[PATH_MAX];
    unsigned char* conf_file = &(conf_file_c[0]);
    memset( conf_file_c, 0, PATH_MAX );

    unsigned char pid_file_c[PATH_MAX];
    unsigned char* pid_file = &(pid_file_c[0]);
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
                if (  NULL == (pid_file = (unsigned char*)strndup(optarg,PATH_MAX))  ) {
                    errx( 1, "strndup: failed to set pid-file override parameter.\n" );
                }
                memcpy( spa_process.pidfile_path, pid_file, strnlen((const char*)pid_file,PATH_MAX) );
                break;
            case 'c':
                if (  NULL == (conf_file = (unsigned char*)strndup(optarg,PATH_MAX))  ) {
                    errx( 1, "strndup: failed to set config-file override parameter.\n" );
                }
                break;
        }
    }


    // Load the service configuration.
    if (  strnlen( (const char*)conf_file, PATH_MAX ) <= 0  ) {
        conf_file = (unsigned char*)p_default_conf;
    }

    // Start logging here based on target log-level.
    //   The program assumes DEBUG logging until the log_level conf is loaded.
    SPAConf__parse( (const char*)conf_file );
    memcpy(  &(spa_process.config_path[0]), conf_file, strnlen((const char*)conf_file,PATH_MAX)  );

    if ( conf_file != (unsigned char*)p_default_conf )
        free( conf_file );
    conf_file = NULL;

    __debuglog(
        write_log( "Checking conf flags register for config load success.\n", NULL );
    )
    if ( IS_CONFIG_LOADED ) {
        write_log( "===== CSPAuthD configuration loaded successfully! =====\n", NULL );
    } else {
        write_error_log( "CSPAuthD configuration failed to load. Exiting.\n", NULL );
    }


    // If daemonization was requested, do that now before listening.
    __debuglog(  write_log( "Checking daemonization request.\n", NULL );  )
    if ( IS_DAEMONIZED )
        daemonize();


    // Create the monitoring thread for keeping track of replays.
    __debuglog(  write_log( "Initializing replay monitor thread.\n", NULL );  )
    if (  EXIT_SUCCESS != SPAReplay__init()  ) {
        write_error_log( "Failed to create the replay monitor thread. Exiting.\n", NULL );
    }


    // Begin the listening process based on the configuration parameters.
    spawn_socket();


    // Enter the primary application loop. This continues until stopped by a signal.
    //   Each connection received spins off a handler thread, so the socket is non-blocking.
    //   TODO: implement a maximum thread count?
    __debuglog(  write_log( "Entering main program iteration loop.\n", NULL );  )

    size_t nbytes;

    unsigned char recv_buffer[PACKET_BUFFER_SIZE];
    unsigned char send_buffer[PACKET_BUFFER_SIZE];

    struct sockaddr_in6 clientaddr;

    while ( 1 ) {
        __debuglog(
            write_log( "Clearing send/recv buffers with memory size %d.\n", PACKET_BUFFER_SIZE );
        )

        memset( &nbytes, 0, sizeof(size_t) );
        memset( &recv_buffer[0], 0, PACKET_BUFFER_SIZE );
        memset( &send_buffer[0], 0, PACKET_BUFFER_SIZE );
        memset( &clientaddr, 0, sizeof(struct sockaddr_in6) );

        __verboselog(  write_log( "Main thread: Waiting for new data.\n", NULL );  )
        if ( AF_INET == listen_family ) {
            int clientaddrlen = sizeof(struct sockaddr_in6);
            if (
                (nbytes = recvfrom( mainsockfd, recv_buffer, PACKET_BUFFER_SIZE,
                    MSG_WAITALL, (struct sockaddr*)&clientaddr, (socklen_t*)&clientaddrlen )) < 0
            ) {
                write_error_log_append( "recv", NULL );
            }
        } else {
            int clientaddrlen = sizeof(struct sockaddr_in);
            struct sockaddr_in* p_sin4 =
                (struct sockaddr_in*)calloc( 1, sizeof(struct sockaddr_in) );

            if (
                (nbytes = recvfrom( mainsockfd, recv_buffer, PACKET_BUFFER_SIZE,
                    MSG_WAITALL, (struct sockaddr*)p_sin4, (socklen_t*)&clientaddrlen )) < 0
            ) {
                write_error_log_append( "recv", NULL );
            }

            // Convert the v4 socket to v6 so it can be used universally.
            //   It gets converted back later as needed.
            struct sockaddr_in6* p_sin6 =
                (struct sockaddr_in6*)calloc( 1, sizeof(struct sockaddr_in6) );

            p_sin6->sin6_family = AF_INET6;
            p_sin6->sin6_port = p_sin4->sin_port;
            p_sin6->sin6_addr.s6_addr[10] = 0xFF;
            p_sin6->sin6_addr.s6_addr[11] = 0xFF;

            memcpy( &((p_sin6->sin6_addr).s6_addr[12]), &(p_sin4->sin_addr), sizeof(char)*4 );
            memcpy( &clientaddr, p_sin6, sizeof(struct sockaddr_in6) );

            free( p_sin6 );
            free( p_sin4 );
        }
        // Usually ridiculous numbers from the socket indicate a signal was trapped.
        //   In such events, the main thread should just quietly continue to run.
        if (  nbytes < 0 || nbytes > (UINT64_MAX-1)  ) {
            __debuglog( write_log( "Received 0 or > uint64_t size packet -- '%lu' bytes "
                "-- usually a SIGHUP on the socket.\n", nbytes ); )
            continue;
        }

        __verboselog(
            char client_addr[INET6_ADDRSTRLEN];
            memset( &client_addr[0], 0, INET6_ADDRSTRLEN );

            inet_ntop( AF_INET6, &(clientaddr.sin6_addr), client_addr, INET6_ADDRSTRLEN );
            write_log( "Received %lu bytes of UDP socket data from '%s' on port '%d'.\n",
                nbytes, client_addr, clientaddr.sin6_port );
        )

        if (  nbytes < SPA_PACKET_MIN_SIZE || nbytes > SPA_PACKET_MAX_SIZE  ) {
            __verboselog(
                write_log( "Invalid SPA packet length. Expected between %lu and"
                    " %lu bytes of data.\n", SPA_PACKET_MIN_SIZE, SPA_PACKET_MAX_SIZE );
            )
            continue;
        } else if (  EXIT_SUCCESS != pre_packet_verify( &recv_buffer[0] )  ) {
            __verboselog(
                write_log( "Detected an invalid UDP packet format. Discarding data.\n", NULL );
            )
            continue;
        }

        // Receive and parse the packet; fill in the meta information to pass to the thread.
        __debuglog(
            write_log( "Generating packet meta-structure for thread.\n", NULL );
        )
        spa_packet_meta_t* p_spa_meta = (spa_packet_meta_t*)calloc( 1, sizeof(spa_packet_meta_t) ) ;

        memcpy( &(p_spa_meta->clientaddr), &clientaddr, sizeof(struct sockaddr_in6) );
        memcpy( &(p_spa_meta->packet), recv_buffer, sizeof(spa_packet_t) );

        __debuglog(  write_log( "Generating packet ID.\n", NULL );  )
        p_spa_meta->packet_id = generate_packet_id();
        __debuglog(  write_log( "Got packet ID tag: |%lu|\n", p_spa_meta->packet_id );  )

        // Spin off a detached thread to handle the SPA.
        __debuglog (
            packet_log( p_spa_meta->packet_id,
                "Creating detached pthread for SPA packet event.\n", NULL );
        )

        pthread_attr_t tattr;
        pthread_attr_init( &tattr );
        pthread_attr_setdetachstate( &tattr, 1 );
        pthread_t t;

        int rc = pthread_create( &t, &tattr, handle_packet, p_spa_meta );

        // Clean up and get ready for the next packet to handle.
        pthread_attr_destroy( &tattr );
        __debuglog(  write_log( "Post-spawn (thread afterbirth) cleanup.\n", NULL );  )
        if ( rc != 0 ) {
            __debuglog(
                write_log( "Problem using pthread_create to create detached "
                    "packet handling thread.\n", NULL );
            )
            free( p_spa_meta );
        }
    }

    // OK.
    __debuglog(
        write_log( "Application broke from main thread iteration. Exiting.\n", NULL );
    )
    return 0;
}



// Packet handling function for thread.
void* handle_packet( void* p_packet_meta ) {
        // Make sure the conf is not actively being reloaded or is having an issue.
        if (  !(IS_CONFIG_LOADED)  ) {
            free( p_packet_meta );
            __quietlog(
                write_syslog( LOG_WARNING, "WARNING: Unable to process incoming"
                    " packet while configuration unloaded!\n", NULL );
            )
            return NULL;
        }


        // Set up shorthand references to packet details.
        spa_packet_t* p_packet = &(((spa_packet_meta_t*)p_packet_meta)->packet);
        struct sockaddr_in6* clientaddr = &(((spa_packet_meta_t*)p_packet_meta)->clientaddr);
        uint64_t packet_id = ((spa_packet_meta_t*)p_packet_meta)->packet_id;

        char client_addr[INET6_ADDRSTRLEN];
        memset( client_addr, 0, INET6_ADDRSTRLEN );

        inet_ntop( AF_INET6, &(clientaddr->sin6_addr), client_addr, INET6_ADDRSTRLEN );

        __normallog(
            packet_log( packet_id, "Received SPA packet from '%s', port '%d'.\n",
                client_addr, clientaddr->sin6_port );
        )


        // Get string-like fields and forcibly null-terminate them.
        unsigned char username[SPA_PACKET_USERNAME_SIZE+1];
        memset( username, 0, SPA_PACKET_USERNAME_SIZE+1 );

        memcpy( username, p_packet->username, SPA_PACKET_USERNAME_SIZE );
        username[SPA_PACKET_USERNAME_SIZE] = '\0';

        // This is not necessary to null-term; it's not a string.
        unsigned char signature[SPA_PACKET_HASH_SIZE];
        memset( signature, 0, SPA_PACKET_HASH_SIZE );
        memcpy( signature, p_packet->packet_hash, SPA_PACKET_HASH_SIZE );


        __verboselog(
            unsigned char sigtohex[(SPA_PACKET_HASH_SIZE*2) + 1];
            memset( sigtohex, 0, (SPA_PACKET_HASH_SIZE*2)+1 );

            for ( int i = 0; i < SPA_PACKET_HASH_SIZE; i++ )
                snprintf( (char*)&(sigtohex[i*2]), 3, "%02x", (unsigned char)(p_packet->packet_hash[i]) );
            sigtohex[SPA_PACKET_HASH_SIZE*2] = '\0';

            packet_log( packet_id, "+++ Username: %s\n", username );
            packet_log( packet_id, "+++ Timestamp: %lu\n", p_packet->client_timestamp );
            packet_log( packet_id, "+++ Requested ACT_OPT: %d_%d\n",
                p_packet->request_action, p_packet->request_option );
            packet_log( packet_id, "+++ Hash (sha256): %s\n", sigtohex );
#ifdef DEBUG
            fprintf( stderr, "Hexdumping packet hash:\n" );
            __debuglog(  print_hex( p_packet->packet_hash, SPA_PACKET_HASH_SIZE );  )
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

        // Check timestamp.
        if (  EXIT_SUCCESS != verify_timestamp( packet_id, p_packet->client_timestamp )  ) {
            __normallog(
                packet_syslog( packet_id, LOG_NOTICE,
                    "Inbound packet failed timestamp verification.\n", NULL );
            )

            send_response( packet_id, clientaddr, SPA_CODE_BAD_TIMESTAMP, "Invalid timestamp" );
            goto handle_packet_cleanup;
        }

        // Validate the username and get the user object.
        spa_user_t* p_user_data = SPAUser__get( username );
        if (  p_user_data == NULL || EXIT_SUCCESS != verify_username( packet_id, username )  ) {
            __normallog(
                packet_syslog( packet_id, LOG_NOTICE,
                    "Could not fetch configuration settings for user '%s'.\n", username );
            )

            send_response( packet_id, clientaddr, SPA_CODE_INVALID_USER, "Invalid or illegal user" );
            goto handle_packet_cleanup;
        }

        // Verify the packet hash by calculating it locally.
        if (  EXIT_SUCCESS != verify_packet_hash( packet_id, p_packet )  ) {
            __normallog(
                packet_syslog( packet_id, LOG_NOTICE,
                    "Packet sha256 hash mismatch.\n", NULL );
            )

            send_response( packet_id, clientaddr, SPA_CODE_HASH_MISMATCH, "sha256 mismatch" );
            goto handle_packet_cleanup;
        }

        // Ensure this isn't a replayed request packet.
        if (  EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_PREVENT_REPLAY )  ) {
            __verboselog(
                packet_log( packet_id, "+++ Checking packet hash for replays.\n", NULL );
            )

            if (  EXIT_SUCCESS != SPAReplay__check( p_packet->packet_hash )  ) {
                __normallog(
                    packet_syslog( packet_id, LOG_NOTICE, "Packet replay detected. "
                        "Same hash within last '%d' seconds.\n", spa_conf.validity_window );
                )

                send_response( packet_id, clientaddr, SPA_CODE_REPLAYED, "Replay detected" );
                goto handle_packet_cleanup;
            }
        }

        // Validate the requested action and option.
        spa_action_t* p_spa_action =
            (spa_action_t*)calloc( 1, sizeof(spa_action_t) );
        if (  EXIT_SUCCESS != verify_action( packet_id, p_spa_action, p_packet->request_action )  ) {
            __normallog(
                packet_syslog( packet_id, LOG_NOTICE, "Action ID '%d' is not a "
                    "loaded or valid action.\n", p_packet->request_action );
            )

            send_response( packet_id, clientaddr, SPA_CODE_INVALID_ACTION, "Invalid action ID" );
            goto handle_packet_cleanup;
        }

        // Check the user pubkey.
        if (  EXIT_SUCCESS != verify_pubkey( packet_id, p_user_data )  ) {
            __normallog(
                packet_syslog( packet_id, LOG_NOTICE, "User '%s' does not have a "
                    "valid public key.\n", username );
            )

            send_response( packet_id, clientaddr, SPA_CODE_INVALID_PKEY, "Invalid user public key" );
            goto handle_packet_cleanup;
        }

        // Check the packet signature against the user's pubkey.
        if (  EXIT_SUCCESS != verify_signature( packet_id, p_packet, p_user_data )  ) {
            __normallog(
                packet_syslog( packet_id, LOG_NOTICE, "Packet crypto "
                    "signature failed to verify.\n", NULL );
            )

            send_response( packet_id, clientaddr, SPA_CODE_INVALID_SIGNATURE, "Crypto signature invalid" );
            goto handle_packet_cleanup;
        }

        // Confirm the user is authorized to run that command.
        if (
            EXIT_SUCCESS != verify_authorization( packet_id, p_user_data,
                p_packet->request_action, p_packet->request_option )
        ) {
            __normallog(
                packet_syslog( packet_id, LOG_NOTICE, "User '%s' is not authorized to perform "
                    "action '%d' with option '%d'.\n",
                    username, p_packet->request_action, p_packet->request_option );
            )
            // Issue a response, depending on the program MODE setting.
            send_response( packet_id, clientaddr, SPA_CODE_NOT_AUTHORIZED, (char*)"User is not authorized" );
            goto handle_packet_cleanup;
        }


        // If applicable, record the packet signature so it cannot be used again.
        if (  EXIT_SUCCESS == SPAConf__get_flag( SPA_CONF_FLAG_PREVENT_REPLAY )  ) {
            __verboselog(
                packet_log( packet_id, "+++ Recording packet hash "
                    "into the time-based linked list.\n", NULL );
            )
            SPAReplay__add( p_packet->packet_hash, p_packet->client_timestamp );
        }


        // Issue a response, depending on the program MODE setting.
        //   This should be done _before_ performing the action, since an authorized
        //   function may have a delay involved.
        if (
            EXIT_SUCCESS != send_response( packet_id, clientaddr,
                SPA_CODE_SUCCESS, "Successful action authorization" )
        ) {
            goto handle_packet_cleanup;
        }


        // Actually perform the action as requested. This will take care of all string expansions as needed.
        __quietlog(
            packet_syslog(
                packet_id, LOG_NOTICE,
                "Processing authorized SPA packet from '%s', user '%s', function %d:%d\n",
                client_addr, username, p_packet->request_action, p_packet->request_option
            );
        )
        if (  EXIT_SUCCESS != SPAAction__perform( p_spa_action, p_packet_meta, &listen_family )  ) {
            __normallog(
                packet_syslog( packet_id, LOG_NOTICE,
                    "Failed to perform the authorized function request.\n", NULL );
            )
            goto handle_packet_cleanup;
        } else {
            __quietlog(
                packet_syslog( packet_id, LOG_NOTICE,
                    "Authorized function %d:%d performed successfully. Cleaning up.\n",
                    p_packet->request_action, p_packet->request_option );
            )
        }


        // End the thread.
        __debuglog(
            packet_log( packet_id, "Finished thread processing "
                "successfully with no code jumps.\n", NULL );
        )

        handle_packet_cleanup:
            free( p_packet_meta );
            __debuglog(  write_log( "Ending thread.\n", NULL );  )
            return NULL;
}



// Small function to generate a random 64-bit packet ID.
//   Helps to track a packet when simultaneous SPA packets are being processed.
uint64_t generate_packet_id() {
    uint64_t r = 0;

    for ( int i = 0; i< 64; i+= RAND_MAX_WIDTH ) {
        r <<= RAND_MAX_WIDTH;
        r ^= (unsigned)rand();
    }

    return r;
}



// Send a response to the issuing SPA client.
int send_response(
    uint64_t packet_id,
    struct sockaddr_in6* p_clientaddr,
    uint16_t response_code,
    char* response_msg
) {
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
    )
# endif

    // Just don't do anything for 'dead' mode. It's completely silent, so it's ignored in this conditional.
    if ( dead == spa_conf.mode ) {
        __debuglog(
            packet_log( packet_id, "Application running in 'dead' mode "
                "-- not issuing packet response.\n", NULL );
        )
        return EXIT_SUCCESS;
    }


    // Create the response packet.
    spa_response_packet_t* p_resp_packet =
        (spa_response_packet_t*)calloc( 1, sizeof(spa_response_packet_t) );

    uint8_t msglen = (uint8_t)(strnlen( response_msg, (SPA_RESPONSE_STRLEN-1) ));

    p_resp_packet->server_version = SPA_SERVER_VERSION;

    p_resp_packet->response_code = response_code;

    p_resp_packet->reserved = 0x0000;

    time_t now;
    time( &now );
    uint64_t current_time = (uint64_t)now;
    p_resp_packet->timestamp = current_time;

    p_resp_packet->packet_id = packet_id;

    memcpy( &(p_resp_packet->response_data[0]), response_msg, msglen );
    p_resp_packet->response_data[SPA_RESPONSE_STRLEN-1] = '\0';   //force null-term


    if ( stealthy == spa_conf.mode ) {
        // Responds only to successful SPA actions.
        if (  response_code != SPA_CODE_SUCCESS ) {
            __debuglog(
                packet_log( packet_id, "Stealthy mode enabled and this packet "
                    "wasn't valid. Staying quiet.\n", NULL );
            )
            goto __send_response_success;
        }
    } else if ( helpful == spa_conf.mode ) {
        // Responds only to successful SPA actions and SPA packets which have a good signature but lack authorization.
        if ( response_code != SPA_CODE_SUCCESS
            && response_code != SPA_CODE_NOT_AUTHORIZED
        ) {
            __debuglog(
                packet_log( packet_id, "Helpful mode enabled and this packet "
                    "wasn't authorized or successful. Staying quiet.\n", NULL );
            )
            goto __send_response_success;
        }
    } else if ( noisy == spa_conf.mode ) {
        // Needs a valid SPA packet format to send a response, whether the packet is successful or not.
    } else {
        __normallog(
            packet_syslog( packet_id, LOG_WARNING, "WARNING: The application mode could"
                " not be determined. Got mode '%d'.\n", spa_conf.mode );
        )
        goto __send_response_failed;
    }

    // Now, actually send the populated response data.
# ifdef DEBUG
    __debuglog(
        packet_log( packet_id, "Sending response datagram "
            "with payload hexdump:\n", NULL );
        )
        print_hex( (unsigned char*)p_resp_packet, sizeof(spa_response_packet_t) );
# endif

    int sentbytes = -1;
    if ( AF_INET == listen_family ) {
        struct sockaddr_in* p_ip4 =
            (struct sockaddr_in*)calloc( 1, sizeof(struct sockaddr_in) );
        p_ip4->sin_family = AF_INET;
        p_ip4->sin_port = p_clientaddr->sin6_port;
        memcpy( &p_ip4->sin_addr, &p_clientaddr->sin6_addr.s6_addr[12], 4 );

# ifdef DEBUG
        __debuglog(  printf( "=== Dumping sendto sockaddr_in:\n" );  )
        print_hex( (unsigned char*)p_ip4, sizeof(struct sockaddr_in) );
# endif

        sentbytes = sendto( mainsockfd, (char*)p_resp_packet, sizeof(spa_response_packet_t),
            0, (struct sockaddr*)p_ip4, (socklen_t)sizeof(struct sockaddr_in) );
        free( p_ip4 );
    } else {

# ifdef DEBUG
    __debuglog(  printf( "=== Dumping sendto sockaddr_in6:\n" );  )
    print_hex( (unsigned char*)p_clientaddr, sizeof(struct sockaddr_in6) );
# endif

        sentbytes = sendto( mainsockfd, (char*)p_resp_packet, sizeof(spa_response_packet_t),
            0, (struct sockaddr*)p_clientaddr, (socklen_t)sizeof(struct sockaddr_in6) );
    }

    if ( sentbytes < 0 ) {
        __normallog(
            packet_syslog( packet_id, LOG_WARNING, "WARNING: Attempted to send"
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



// Spawn the listening SPA service socket for receiving network packets.
void spawn_socket() {
    int sockfd;

    struct sockaddr_in6 sock6;
    memset( &sock6, 0, sizeof(struct sockaddr_in6) );

    // If rebinding the socket, attempt to close the previous one so it can rebind.
    if ( mainsockfd != -1 ) {
        if (  close( mainsockfd ) < 0  ) {
            write_error_log_append( "socket-close", NULL );
        }
        mainsockfd = -1;
    }

    // Get socket file descriptor.
    __debuglog(
        write_log( "Receiving socket file descriptor for UDP bind.\n", NULL );
    )
    if (
        -1 == (sockfd = socket(((IS_IPV4_ONLY) ? AF_INET : AF_INET6), SOCK_DGRAM, 0))
    )  write_error_log_append( "socket", NULL );

    mainsockfd = sockfd;
    __debuglog(  write_log( "Got sockfd: %d.\n", sockfd );  )

    // Set socket information according to configuration.
    sock6.sin6_family = ((IS_IPV4_ONLY) ? AF_INET : AF_INET6);
    sock6.sin6_port = htons(
        (spa_conf.bind_port <= 0 ? SPA_DEFAULT_BIND_PORT : spa_conf.bind_port)
    );

    // More socket option settings.
    __debuglog( write_log( "Setting socket options.\n", NULL ); )
    char* p_if = &(spa_conf.bind_interface[0]);
    int is_any_interface = OFF;

    // Set depending on the bind interface's name.
    if (  0 != strncmp( p_if, "any", IF_NAMESIZE )  ) {
        __normallog(  write_log( "* Binding to interface '%s'.\n", p_if );  )

        if (
            ( setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE,
            p_if, strnlen((const char*)p_if,IF_NAMESIZE)) ) < 0
        )  write_error_log_append( "setsockopt:BINDTODEVICE", NULL );
    } else {
        is_any_interface = ON;
        __normallog(  write_log( "* Binding to any interface.\n", NULL );  )
    }

    // Even more socket option settings.
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

    // Bind address settings. If one is specified, it must be found on the system to use.
    char* p_bindaddr = &(spa_conf.bind_address[0]);
    if (  0 == strncmp( p_bindaddr, "any", INET6_ADDRSTRLEN )  ) {
        // Things are so simple when the bind address is 'any'...
        __normallog(  write_log( "* Setting bind address to any.\n", NULL );  )
        sock6.sin6_addr = in6addr_any;
    } else {
        __debuglog(
            write_log( "* Attempting to bind to address '%s'.\n", p_bindaddr );
        )

        struct ifaddrs* p_ifas = (struct ifaddrs*)calloc( 1, sizeof(struct ifaddrs) );
        if (  0 != getifaddrs( &p_ifas )  ) {
            write_error_log_append( "getifaddrs", NULL );
        } else if ( NULL == p_ifas ) {
            write_error_log( "Tried to get interface addresses but got NULL.\n", NULL );
        }

        // Interpret the given address for validity.
        int bind_addr_fam = AF_INET;
        for ( char* p = p_bindaddr; p < (p_bindaddr+INET6_ADDRSTRLEN); p++ ) {
            if ( ':' == *p )
                bind_addr_fam = AF_INET6;
        }
        if ( bind_addr_fam != AF_INET && (IS_IPV4_ONLY) ) {
            write_error_log( "The given bind_address '%s' is not an IPv4 address, and"
                " the application is set to only use IPv4.\n", p_bindaddr );
        }

        // Read the interpreted bind address into this 'disc'over void ptr.
        void* p_bindaddr_disc = calloc( 1, sizeof(struct in6_addr) );

        int interp_rc = inet_pton( bind_addr_fam, p_bindaddr, p_bindaddr_disc );
        if (  interp_rc != 1 ) {
            write_error_log( "The given bind_address '%s' is not a valid IPv%c address.\n",
                p_bindaddr, (AF_INET == bind_addr_fam ? '4' : '6') );
        }

        __debuglog(
            write_log( "*** Enumerating local interface addresses.\n", NULL );
        )

        int is_bindaddr_found = OFF;
        struct ifaddrs* p_nextifa = p_ifas;

        do {
            // If the program binds to a specific interface, skip this interface if its name doesn't match.
            if ( OFF == is_any_interface ) {
                if (  0 != strncmp( &(p_nextifa->ifa_name[0]), p_if, IF_NAMESIZE )  )
                    continue;
            }

            // Skip non IPv4 or IPv6 family addresses.
            short int addrfam = p_nextifa->ifa_addr->sa_family;
            if ( addrfam != AF_INET && addrfam != AF_INET6 )
                continue;

            // Get the address based off the family.
            void* p_cmp_addr = calloc( 1, sizeof(struct in6_addr) );
            if ( AF_INET == addrfam )
                memcpy( p_cmp_addr,
                    &(((struct sockaddr_in*)p_nextifa->ifa_addr)->sin_addr), sizeof(struct in_addr) );
            else
                memcpy( p_cmp_addr,
                    &(((struct sockaddr_in6*)p_nextifa->ifa_addr)->sin6_addr), sizeof(struct in6_addr) );

            // Make sure the IFADDR is a human-readble address, and output it if debug-mode.
            char ifaddr[INET6_ADDRSTRLEN];
            memset( &ifaddr[0], 0, INET6_ADDRSTRLEN );

            if (
                NULL == inet_ntop( addrfam, p_cmp_addr, ifaddr,
                    (addrfam == AF_INET ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN) )
            ) {
                free( p_cmp_addr );
                continue;
            }
            __debuglog(
                write_log( "***** Discovered local address '%s', interface '%s'.\n",
                    ifaddr, p_nextifa->ifa_name );
            )

            // Now actually compare the addresses. If it matches, copy it in from the ptr and proceed.
            if (
                0 == memcmp( p_bindaddr_disc, p_cmp_addr,
                    (AF_INET == addrfam ? sizeof(struct in_addr) : sizeof(struct in6_addr)) )
            ) {
                __normallog(
                    write_syslog( LOG_NOTICE, "* Using local bind address '%s', "
                        "interface '%s'.\n", ifaddr, p_nextifa->ifa_name );
                )

                memcpy( &(sock6.sin6_addr), p_cmp_addr,
                    (AF_INET == addrfam ? sizeof(struct in_addr) : sizeof(struct in6_addr)) );

                free( p_cmp_addr );

                is_bindaddr_found = ON;
                break;
            }

            free( p_cmp_addr );

        // Loops until it finds a matching bind address or there are no more to parse.
        } while (  NULL != (p_nextifa = p_nextifa->ifa_next)  );

        // Free some resources as needed.
        free( p_bindaddr_disc );
        freeifaddrs( p_ifas );

        // If there was a problem, this is it...
        if ( ON != is_bindaddr_found ) {
            if ( ON == is_any_interface ) {
                write_error_log( "The bind_address '%s' was not found "
                    "on the local system.\n", p_bindaddr );
            } else {
                write_error_log( "The bind_address '%s' is not an address "
                    "on the interface '%s'.\n", p_bindaddr, p_if );
            }
        }
    }


    __debuglog(
        write_log( "Attempting to bind to port '%d' per "
            "service config.\n", spa_conf.bind_port );
    )

    // Now actually perform the bind based on the address type.
    int bindres = -1;
    if ( IS_IPV4_ONLY ) {
        struct sockaddr_in* p_sock4 = (struct sockaddr_in*)calloc( 1, sizeof(struct sockaddr_in) );
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

    // If there was a problem binding, halt.
    if ( bindres < 0 ) {
        write_error_log_append( "bind", NULL );
    }

    // All done!
    __normallog(
        write_log( "Ready to receive connections!\n", NULL );
    )
}



// Register signals with the daemon.
void register_signals() {
    struct sigaction sa;
    memset( &sa, 0, sizeof(struct sigaction) );

    sa.sa_handler = handle_signal;
    sigaction( SIGINT,  &sa, NULL );
    sigaction( SIGTERM, &sa, NULL );
    sigaction( SIGHUP,  &sa, NULL );
}

// Actually handle signals raised to the daemon process.
void handle_signal( int signal ) {
    if ( SIGHUP == signal ) {
        write_syslog( LOG_WARNING, "Received signal SIGHUP. Reloading configuration...\n", NULL );

        __debuglog(
            write_log( "Reading process meta-info for configuration path.\n", NULL );
        )

        unsigned char conf_path_c[PATH_MAX];
        unsigned char* conf_path = &conf_path_c[0];
        memset( conf_path, 0, PATH_MAX );

        memcpy( conf_path, &(spa_process.config_path),
            strnlen( spa_process.config_path, PATH_MAX )  );
        __debuglog(  write_log( "Got conf path: |%s|\n", conf_path );  )

        SPAConf__clear();
        SPAConf__parse( (const char*)conf_path );

        spawn_socket();   //rebind according to new conf params

        __normallog(
            write_log( "Config and socket reloaded. Ready to receive connections!\n", NULL );
        )
    } else {
        // Any other registered signal terminates the process.
        write_syslog( LOG_WARNING, "Received signal '%d'. Goodbye.\n", signal );
        exit( 0 );
    }
}

// Initialize the syslog feature.
void syslog_init() {
    openlog(
        (const char*)(&(spa_process.syslog_tag[0])),
        (LOG_CONS | LOG_NDELAY | LOG_PID),
        LOG_DAEMON
    );

    write_syslog( LOG_NOTICE, "Initializing.\n", NULL );
}



// Send the process to the background using a series of forks.
void daemonize() {
    FILE* fp_pidfile;
    pid_t pid;

    __debuglog(  write_log( "Daemonizing.\n", NULL );  )
    __debuglog(  write_log( "Checking pidfile at: |%s|\n", spa_process.pidfile_path );  )
    if (  strnlen( spa_process.pidfile_path, PATH_MAX ) <= 0  )
        write_error_log( "Failed to daemonize: no PID file is "
            "defined with the '-p' option.\n", NULL );

    __debuglog(  write_log( "First fork...\n", NULL );  )
    pid = fork();
    if ( pid < 0 )
        write_error_log( "Failed to daemonize: first fork.\n", NULL );
    if ( pid > 0 )
        exit( 0 );

    __debuglog(  write_log( "setsid\n", NULL );  )
    if ( setsid() < 0 )
        write_error_log_append( "setsid", NULL );

    __debuglog(  write_log( "chdir to '/'\n", NULL );  )
    if ( chdir("/") < 0 )
        write_error_log_append( "chdir", NULL );

    __debuglog(  write_log( "umask(0);\n", NULL );  )
    umask( 0 );

    // Trash STDIN -- other handles can write out. Syslog/Jounal handles logging.
    __debuglog(  write_log( "Redirecting STDIN to /dev/null\n", NULL );  )
    freopen( "/dev/null", "r", stdin );

    __debuglog(  write_log( "Second fork...\n", NULL );  )
    pid = fork();
    if ( pid < 0 )
        write_error_log( "Failed to daemonize: second fork.\n", NULL );
    if ( pid > 0 )
        exit( 0 );

    __debuglog(  write_log( "getpid\n", NULL );  )
    pid = getpid();
    __debuglog(  write_log( "Received process ID: %d\n", pid );  )

    __debuglog(  write_log( "fopen PID file handle for: |%s|\n", spa_process.pidfile_path );  )
    if (  NULL == (fp_pidfile = fopen( spa_process.pidfile_path, "w+" ))  )
        write_error_log_append( "fopen", NULL );

    __debuglog( write_log( "Writing PID value to PID file.\n", NULL ); )
    if (  fprintf( fp_pidfile, "%d", pid) < 0  )
        write_error_log( "Failed to write to PID file.\n", NULL );

    __debuglog( write_log( "fclose PID file handle.\n", NULL ); )
    if (  EOF == fclose( fp_pidfile )  )
        write_error_log( "Failed to close the PID file handle.\n", NULL );
}
