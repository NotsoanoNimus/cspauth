/*
 * Main SPA protocol client functions and implementations.
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


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <getopt.h>
#include <ctype.h>
#include <time.h>
#include <err.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "../spa.h"
#include "../integrity.h"



#define __debug( ... ) \
	if ( is_debug == ON ) {  __VA_ARGS__ }

#define MAX_TARGET_STRLEN 256

#define CLIENT_MAX_WAIT_TIME 300
#define CLIENT_MIN_WAIT_TIME 10



void __print_usage_info() {
    printf(
        "Usage: cspauth [-?hx46] {-k key-file} {-f function} {-u username} {-t target}\n"
        "                   [-w wait-time] [-p port] [-d data]\n"
        "\n"
        "Sends a Single Packet Authorization request to the target host for the requested\n"
        "  function, with the specified credentials. Responses can be awaited, or the\n"
        "  client can be set to 'fire-and-forget' the request.\n"
        "\n"
        "Options:\n"
        "    -h, --help      Display this help.\n"
        "    -x, --debug     Display client debugging information.\n"
        "    -4/-6           Force an IPv4 or IPv6 connection only.\n"
        "    -k, --keyfile   Certificate private key-file associated with the username.\n"
        "    -f, --function  The action-option combination to perform on the remote server,\n"
        "                      which must be specified in the format 'action-id:option-id'.\n"
        "    -u, --user      The username authorized to perform the requested function, with\n"
        "                      the specified private key-file.\n"
        "    -t, --target    The hostname or IPv4/6 address of the target CSPAuthD server.\n"
        "    -p, --port      The (optional) target port to send the request to. This option,\n"
        "                      if unspecified, sets to the default CSPAuthD port of 41937.\n"
        "    -w, --wait      The time in seconds to wait for a response from the SPA server.\n"
        "                      If unspecified, the client won't wait for a response at all.\n"
        "    -d, --data      The data to send with the packet. If unspecified, the client\n"
        "                      will generate randomized data to send to the server.\n"
        "\n"
        "\n"
    );
    exit( 1 );
}



uint16_t get_valid_uint16( char* str, char* type );
void register_signals();
void handle_signal( int signal );

// Signs a packet and stores its signature on the pointed packet.
int sign_packet( BYTE* key_file, spa_packet_t* p_packet, int is_debug );

# ifdef DEBUG
void print_hex( BYTE* data, size_t len );
# endif



int main( int argc, char** argv ) {
    // Initial registrations and client setup.
    register_signals();
    openssl_init();
    setbuf( stdout, NULL );
    setbuf( stderr, NULL );


    // Parse options.
    struct option cli_long_opts[] = {
        { "help",      no_argument,        NULL,  'h' },
        { "debug",     no_argument,        NULL,  'x' },
        { "wait",      required_argument,  NULL,  'w' },
        { "keyfile",   required_argument,  NULL,  'k' },
        { "function",  required_argument,  NULL,  'f' },
        { "user",      required_argument,  NULL,  'u' },
        { "target",    required_argument,  NULL,  't' },
        { "port",      required_argument,  NULL,  'p' },
        { "data",      required_argument,  NULL,  'd' },
        { 0,           0,                  0,     0   }
    };
    int cli_opt_idx = 0;
    int cli_opt;


    BYTE key_file_c[PATH_MAX];
    BYTE* p_key_file = &key_file_c[0];
    memset( p_key_file, 0, PATH_MAX );

    BYTE user_c[SPA_PACKET_USERNAME_SIZE];
    BYTE* p_user = &user_c[0];
    memset( p_user, 0, SPA_PACKET_USERNAME_SIZE );

    BYTE tgtnode_c[MAX_TARGET_STRLEN];
    BYTE* p_tgtnode = &tgtnode_c[0];
    memset( p_tgtnode, 0, MAX_TARGET_STRLEN );

    BYTE data_c[SPA_PACKET_DATA_SIZE];
    BYTE* p_data = &data_c[0];
    memset( p_data, 0, SPA_PACKET_DATA_SIZE );

    uint16_t tgtport = 0;
    uint16_t action = 0;
    uint16_t option = 1;   //option is assumed as '1' when it's not provided
    uint16_t wait_time = 0;
    int is_debug = OFF;
    int is_ipv4 = OFF;
    int is_ipv6 = OFF;

    // Show help/usage on no parameters.
    if ( argc <= 1 )  __print_usage_info();

	// Parse the options.
	for ( ; ; ) {
		cli_opt = getopt_long( argc, argv, "hx46w:k:f:u:t:p:d:", cli_long_opts, &cli_opt_idx );
		if ( cli_opt == -1 )  break;
		switch ( cli_opt ) {
			case '?':
			case 'h':
			default :   //(flag) help/usage
				__print_usage_info();
				break;

			case 'x':   //(flag) debug
				if ( is_debug == ON )
					errx( 1, "The debug option can only be specified once.\n" );
				is_debug = ON;
				break;

			case '4':   //(flag) ipv4
				if ( is_ipv4 == ON )
					errx( 1, "The IPv4 option can only be specified once.\n" );
				is_ipv4 = ON;
				break;

			case '6':   //(flag) ipv6
				if ( is_ipv6 == ON )
					errx( 1, "The IPv6 option can only be specified once.\n" );
				is_ipv6 = ON;
				break;

			case 'w':   //wait (for SPA server response) for x seconds
				if ( wait_time != 0 )
					errx( 1, "The wait timeout can only be defined once.\n" );

				wait_time = get_valid_uint16( optarg, "Wait timeout" );
				if ( wait_time > CLIENT_MAX_WAIT_TIME )
					errx( 1, "The maximum SPA client wait-time is %d seconds.\n", CLIENT_MAX_WAIT_TIME );
				else if ( wait_time < CLIENT_MIN_WAIT_TIME )
					errx( 1, "The minimum SPA client wait-time is %d seconds.\n", CLIENT_MIN_WAIT_TIME );

				break;

			case 'k':   //keyfile
				if ( strnlen( (const char*)p_key_file, PATH_MAX ) != 0 )
					errx( 1, "Key-file can only be defined once.\n" );

				memcpy( p_key_file, optarg, strnlen(optarg,PATH_MAX) );
				p_key_file[PATH_MAX-1] = '\0';   //force null-term
				break;

			case 'f':   //function
				if ( action != 0 )
					errx( 1, "The function to call cannot be defined twice.\n" );

				const char delim[] = ":";

				char* func = strndup( optarg, 13 );   //never needs to be more than 13 chars
				if ( func == NULL )
					errx( 1, "Function option requires a valid argument.\n" );

				// get action
				char* x = strtok( func, delim );
				action = get_valid_uint16( x, "Function action" );

				// get option (if set)
				char* y = strtok( NULL, delim );
				// If an option is defined, set it if it's valid.
				option = (y != NULL) ? get_valid_uint16( y, "Function option" ) : 1;

				break;

			case 'u':   //user
				if ( strnlen( (const char*)p_user, SPA_PACKET_USERNAME_SIZE ) != 0 )
					errx( 1, "Username can only be defined once.\n" );

				memcpy( p_user, optarg, strnlen(optarg,SPA_PACKET_USERNAME_SIZE) );

				if ( strnlen( (const char*)optarg, SPA_PACKET_USERNAME_SIZE ) > SPA_PACKET_USERNAME_SIZE-1 )
					fprintf( stderr, "WARNING: Given username was longer than the "
						"%d character limit. Value truncated.\n", SPA_PACKET_USERNAME_SIZE-1 );

				p_user[SPA_PACKET_USERNAME_SIZE-1] = '\0';   //force null-term
				break;

			case 't':   //target
				if ( strnlen( (const char*)p_tgtnode, MAX_TARGET_STRLEN ) != 0 )
					errx( 1, "Target address can only be defined once.\n" );

				memcpy( p_tgtnode, optarg, strnlen(optarg,MAX_TARGET_STRLEN) );

				p_tgtnode[MAX_TARGET_STRLEN-1] = '\0';   //force null-term
				break;

			case 'p':   //port
				if ( tgtport != 0 )
					errx( 1, "The target port can only be defined once.\n" );

				tgtport = get_valid_uint16( optarg, "Target port" );
				break;

			case 'd':   //data
				if ( strnlen( (const char*)p_data, SPA_PACKET_DATA_SIZE ) != 0 )
					errx( 1, "Data can only be defined once.\n" );

				memcpy( p_data, optarg, strnlen(optarg,SPA_PACKET_DATA_SIZE) );

				if ( strnlen( (const char*)optarg, SPA_PACKET_DATA_SIZE ) > SPA_PACKET_DATA_SIZE-1 )
					fprintf( stderr, "WARNING: Given data field was longer than the "
						"%d character limit. Value truncated.\n", SPA_PACKET_DATA_SIZE-1 );

				p_data[SPA_PACKET_DATA_SIZE-1] = '\0';   //force null-term
				break;
		}
	}


	// Check that all required variables are initialized.
	if ( action == 0 )
		errx( 1, "The function action must be set to a non-zero option; see the 'f' option.\n" );
	if ( strnlen( (const char*)p_key_file, PATH_MAX ) <= 0 )
		errx( 1, "A valid key-file must be defined with the 'k' option.\n" );
	if ( strnlen( (const char*)p_user, SPA_PACKET_USERNAME_SIZE ) <= 0 )
		errx( 1, "A username must be defined with the 'u' option.\n" );
	if ( strnlen( (const char*)p_tgtnode, MAX_TARGET_STRLEN ) <= 0 )
		errx( 1, "A target IP or hostname must be defined with the 't' option.\n" );
	if ( is_ipv4 == ON && is_ipv6 == ON ) {
		// if both flags are provided, the user just doesn't care about the addr type.
		//   this is the default behavior anyway; no sense in throwing another error, just clear flags
		is_ipv4 = OFF;
		is_ipv6 = OFF;
	}
	FILE* fp = NULL;
	if ( (fp = fopen((const char*)p_key_file,"r")) == NULL )
		errx( 1, "Failed to read key file '%s'.\n", p_key_file );
	fclose( fp );


	// BEING STDOUT CLI OUTPUT WHERE APPLICABLE.
	printf( "\n" );

	// Set defaults as needed.
	if ( tgtport == 0 ) {
		printf( "* Port unspecified; using default cspauthd port of '%d'.\n\n", SPA_DEFAULT_BIND_PORT );
		tgtport = SPA_DEFAULT_BIND_PORT;   //assumes default cspauthd port
	}
	if ( strnlen( (const char*)p_data, SPA_PACKET_DATA_SIZE ) <= 0 ) {
		__debug( printf( "+ Unspecified data string; generating random data.\n" ); )
		// if the data field is not set, randomize the data
		srandom( (unsigned int)time(NULL) );
		for ( BYTE* p = p_data; p < (p_data+SPA_PACKET_DATA_SIZE); p++ )
			*p = (BYTE)(random() & 0xFF);
	}


	// Set up the target address socket.
    struct addrinfo* p_hints = (struct addrinfo*)calloc( 1, sizeof(struct addrinfo) );
	struct addrinfo* p_res   = NULL;   //results **
	struct addrinfo* p_res_i = NULL;   //results iterator

	// If IPv4 is set statically, use that family only. Same for v6. Else, get any returned address
	p_hints->ai_flags = 0;
	if ( is_ipv4 == ON ) {
		printf( "Using IPv4 address family only." );
		p_hints->ai_family = AF_INET;
	} else if ( is_ipv6 == ON ) {
		printf( "Using IPv6 address family only." );
		p_hints->ai_family = AF_INET6;
	} else {
		printf( "Using any address family." );
		p_hints->ai_family = AF_UNSPEC;
		p_hints->ai_flags = AI_ADDRCONFIG;   //get IPs based on local address/adapter configurations
	}
	printf( "\n\n" );
	p_hints->ai_socktype = SOCK_DGRAM;

	// convert the target port to a string safely.
	char port_c[6] = {0};
	snprintf( &port_c[0], 6, "%d", tgtport );
	port_c[5] = '\0';

	__debug( printf( "Getting IPs from input string '%s'.\n", p_tgtnode ); )
	int __addrinfo_rc = getaddrinfo( (const char*)p_tgtnode, &port_c[0], p_hints, &p_res );
	if ( __addrinfo_rc != 0 ) {
		fprintf( stderr, "getaddrinfo: %s\n", gai_strerror(__addrinfo_rc) );
		exit( 1 );
	}

	// iterate the returned address details
    void* p_addr = calloc( 1, sizeof(struct sockaddr_in6) );

    int addrfam = -1;
    char* p_ipchoice = NULL;

    for ( p_res_i = p_res; p_res_i != NULL; p_res_i = p_res_i->ai_next ) {
        void* p_foundaddr = NULL;
        void* p_addr_tmp = NULL;

        if ( p_res_i->ai_family != AF_INET && is_ipv4 == ON )  continue;
        else if ( p_res_i->ai_family != AF_INET6 && is_ipv6 == ON )  continue;

        if ( AF_INET == p_res_i->ai_family ) {
            struct sockaddr_in* p_ip4  = (struct sockaddr_in*)(p_res_i->ai_addr);
            p_ip4->sin_port = htons( tgtport );
            p_foundaddr = &p_ip4->sin_addr;
            p_addr_tmp = p_ip4;
        } else if ( AF_INET6 == p_res_i->ai_family ) {
            struct sockaddr_in6* p_ip6 = (struct sockaddr_in6*)(p_res_i->ai_addr);
            p_ip6->sin6_port = htons( tgtport );
            p_foundaddr = &p_ip6->sin6_addr;
            p_addr_tmp = p_ip6;
        } else  continue;

        char ipstr[INET6_ADDRSTRLEN];
        memset( ipstr, 0, INET6_ADDRSTRLEN );
        if (  NULL != inet_ntop( p_res_i->ai_family, p_foundaddr, ipstr, INET6_ADDRSTRLEN )  ) {
            __debug( printf( "+++++ Got address '%s'\n", ipstr ); )
            if ( -1 == addrfam && NULL != p_addr_tmp ) {
                addrfam = p_res_i->ai_family;
                memcpy( p_addr, p_addr_tmp,
                    ((addrfam == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) );
                p_ipchoice = &ipstr[0];
            }
        }
    }

    if ( NULL == p_ipchoice || -1 == addrfam )
        errx( 1, "No valid addresses matching the specified address family were found.\n" );

# ifdef DEBUG
    __debug(
        printf( "SOCKADDR object dump:\n" );
        print_hex( (BYTE*)p_addr, addrfam == AF_INET
            ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6) );
    )
# endif

    free( p_hints );
    freeaddrinfo( p_res );

    // Create the socket
    __debug( printf( "+++ Creating UDP socket.\n" ); )
    int sockfd = 0;
    if (  -1 == (sockfd = socket(addrfam,SOCK_DGRAM,0))  )
        err( 1, "socket" );

    __debug( printf( "+++++ Socket ready.\n\n" ); )


    // Construct the packet.
    spa_packet_t* p_packet = (spa_packet_t*)calloc( 1, sizeof(spa_packet_t) );

    time_t now;
    time( &now );
    uint64_t timestamp = (uint64_t)now;

    __debug( printf( "+++ Populating packet fields.\n" ); )
    memcpy( &p_packet->packet_data[0], p_data, SPA_PACKET_DATA_SIZE );
    __debug( printf( "+++++ Packet username: '%s'\n", p_user ); )
    memcpy( &p_packet->username, p_user, SPA_PACKET_USERNAME_SIZE );
    __debug( printf( "+++++ Timestamp: %lu\n", timestamp ); )
    p_packet->client_timestamp = timestamp;
    __debug( printf( "+++++ Function action: %d\n", action ); )
    p_packet->request_action = action;
    __debug( printf( "+++++ Function option: %d\n", option ); )
    p_packet->request_option = option;
    __debug( printf( "+++++ Generating packet hash.\n" ); )
    if (  0 >= hash_packet( &p_packet->packet_hash[0], p_packet )  )
        errx( 1, "Failed to hash the SPA packet.\n" );
    __debug( printf( "+++++ Generating packet signature.\n" ); )
    if (  EXIT_SUCCESS != sign_packet( p_key_file, p_packet, is_debug )  )
        errx( 1," Failed to generate packet crypto signature.\n" );
    __debug( printf( "+++ Packet generated and fields populated.\n\n" ); )

    // Calculate the packet size.
    size_t dispatch_len = SPA_PACKET_MIN_SIZE + p_packet->signature_length;

    if (  dispatch_len < SPA_PACKET_MIN_SIZE || dispatch_len > SPA_PACKET_MAX_SIZE  )
        errx( 1, "Illegal packet length. x != %lu <= x <= %lu\n", SPA_PACKET_MIN_SIZE, SPA_PACKET_MAX_SIZE );

# ifdef DEBUG
    __debug(
        printf( "Packet dump '%lu':\n", dispatch_len );
        print_hex( (BYTE*)p_packet, dispatch_len );
    )
# endif


    // Use the socket to send the data.
    printf( "Sending %lu bytes of prepared SPA packet to '[%s]:%d'.\n",
        dispatch_len, p_ipchoice, tgtport );

    int sentbytes = -1;
    sentbytes = sendto(
        sockfd, (BYTE*)p_packet, dispatch_len, 0, (struct sockaddr*)p_addr,
        (socklen_t)( (addrfam == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6) )
    );

    if ( sentbytes < 0 )
        err( 1, "sendto" );

    free( p_addr );
    free( p_packet );
    __debug( printf( "+++++ Sent %d bytes of data.\n", sentbytes ); )

    printf( " === Packet dispatched successfully.\n\n" );


	// Based on application options, either fire-and-forget or wait for a response.
	if ( wait_time > 0 ) {

		__debug( printf( "+++ Setting socket RCVTIMEO option: %d\n", wait_time ); )
        struct timeval* p_tv = (struct timeval*)calloc( 1, sizeof(struct timeval) );

		p_tv->tv_sec = wait_time;
		if ( (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, p_tv, sizeof(struct timeval) )) < 0 )
			err( 1, "setsockopt: SO_RCVTIMEO" );
		free( p_tv );

		size_t recvbytes;
		BYTE recv_buffer[PACKET_BUFFER_SIZE];
		memset( &recv_buffer[0], 0, PACKET_BUFFER_SIZE );

		printf( "Awaiting UDP response from remote server for %d seconds...\n", wait_time );
		int remoteaddrlen = ( (addrfam == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6) );
		if ( (recvbytes = recvfrom( sockfd, recv_buffer, PACKET_BUFFER_SIZE,
				MSG_WAITALL, (struct sockaddr*)&p_addr, (socklen_t*)&remoteaddrlen )) < 0 )
			err( 1, "recvfrom" );
		__debug( printf( "+++++ RECVBYTES: %lu\n", recvbytes ); )

		// Usually ridiculous numbers from the socket indicate a signal was trapped.
		//   In such events, the main thread should just quietly continue to run.
		if ( recvbytes <= 0 || recvbytes > UINT32_MAX-1 ) {
			__debug( printf( "~~~ Received 0 or > uint32_t length packet; invalid response.\n" ); )
			printf( " === Listening socket timed out.\n\n" );
			exit( 0 );
		}

		__debug( printf( "\n+++ Received %lu bytes of UDP response socket data.\n", recvbytes ); )

        if ( recvbytes != sizeof(spa_response_packet_t) )
            errx( 1, " === Received a response packet that was not the expected size. Exiting now.\n\n" );


		// "Cast" and parse the response.
        spa_response_packet_t* p_response =
            (spa_response_packet_t*)calloc( 1, sizeof(spa_response_packet_t) );

        memcpy( p_response, &recv_buffer[0], sizeof(spa_response_packet_t) );
        p_response->response_data[SPA_RESPONSE_STRLEN-1] = '\0';   //force null-term

        printf(
            "\n==================================================================\n"
            "=  RECEIVED SPA RESPONSE:\n"
            "=    Server version: 0x%08x\n"
            "=    Response code:  0x%08x\n"
            "=    Time: %lu\n"
            "=    Log ID: %lu\n"
            "=    ---------------------------------------------\n"
            "=    Message: %s\n=\n"
            "==================================================================\n\n",
            p_response->server_version,
            p_response->response_code,
            p_response->timestamp,
            p_response->packet_id,
            p_response->response_data
        );

        free( p_response );
    } else {
        printf( "No timeout/wait was set; not awaiting a SPA response.\n\n" );
    }


    // Exit success.
    __debug( printf( "\n\n=== DONE ===\n\n" ); )
    exit( 0 );
}



uint16_t get_valid_uint16( char* str, char* type ) {
    if ( str == NULL || strnlen(str,6) > 5 )
        errx( 1, "%s is not valid.\n", type );

    for ( int i = 0; i < strnlen(str,6); i++ ) {
        if ( !isdigit( (int)str[i] ) )
            errx( 1, "%s is not a valid integer.\n", type );
    }

    uint16_t retval = (uint16_t)atoi( str );

    if ( retval < 1 || retval > UINT16_MAX )
        errx( 1, "%s must be between 1 and %d.\n", type, UINT16_MAX );

    return retval;
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
    fprintf( stderr, "Received signal '%d'. Goodbye.\n", signal );
    exit( 0 );
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



// Verify the actual crypto signature attached to the packet.
int sign_packet( BYTE* key_file, spa_packet_t* p_packet, int is_debug ) {
    __debug( printf( "crypto: Checking packet's SHA256 signature with the user's pubkey.\n" ); )

    int rc = -1;
    FILE* fp = NULL;
    EVP_PKEY* pkey = NULL;

    EVP_MD_CTX* mdctx = NULL;
    BYTE* sig = NULL;

    size_t slen = 0;


    __debug( printf( "crypto: Attempting to load PEM private key file '%s'.\n", key_file ); )
    if ( (fp = fopen((const char*)key_file,"r")) == NULL ) {
        fprintf( stderr, "crypto: Failed to load private key file.\n" );
        goto __err;
    }

    __debug( printf( "crypto: Reading PEM from input file pointer.\n" ); )
    if ( (pkey = PEM_read_PrivateKey(fp,NULL,NULL,NULL)) == NULL ) {
        fprintf( stderr, "crypto: Failed to read private key from file.\n" );
        goto __err;
    }

    fclose( fp );


    __debug( printf( "crypto: Creating digest context.\n" ); )
    if ( !(mdctx = EVP_MD_CTX_create()) )  goto __err;

    __debug( printf( "crypto: Initializing digest context.\n" ); )
    if ( EVP_DigestSignInit( mdctx, NULL, EVP_sha256(), NULL, pkey ) != 1 )  goto __err;

    __debug( printf( "crypto: Updating digest context.\n" ); )
    if ( EVP_DigestSignUpdate( mdctx, &p_packet->packet_hash[0], SPA_PACKET_HASH_SIZE ) != 1 )  goto __err;

    __debug( printf( "crypto: Getting final signature buffer length.\n" ); )
    if ( EVP_DigestSignFinal( mdctx, NULL, &slen ) != 1 )  goto __err;

    __debug( printf( "crypto: Allocating _predicted_ space for signature copy.\n" ); )
    if ( !(sig = (BYTE*)OPENSSL_malloc( sizeof(BYTE)*slen )) )  goto __err;

    __debug( printf( "crypto: Generating signature...\n" ); )
    if ( EVP_DigestSignFinal( mdctx, sig, &slen ) != 1 )  goto __err;
    rc = 1;

    // NOTE: slen gets updated in the final signing above. The initial malloc is to get the POTENTIAL signature size.
    if ( slen > SPA_PACKET_MAX_SIGNATURE_SIZE ) {
        fprintf( stderr, "crypto: The final signature exceeds maximum size of %d bytes.\n", SPA_PACKET_MAX_SIGNATURE_SIZE );
        goto __err;
    }

    __debug( printf( "crypto: Got valid packet signature with size of %lu bytes.\n", slen ); )
    p_packet->signature_length = (slen & 0xFFFFFFFF);

    __debug( printf( "crypto: Copying generated signature to packet buffer.\n" ); )
    memcpy( &p_packet->packet_signature[0], sig, sizeof(BYTE)*slen );


    __err:
    if ( sig != NULL )  OPENSSL_free( sig );
    if ( mdctx )  EVP_MD_CTX_destroy( mdctx );
    if ( pkey )  EVP_PKEY_free( pkey );

    if ( rc != 1 ) {
        __debug( printf( "~~~~~ Signature verification failed. Attempting to get why...\n" ); )

        char* openssl_err = (char*)calloc( 1, 128 );

        ERR_error_string_n( ERR_get_error(), openssl_err, 128 );
        __debug( printf( "~~~~~  ---> OpenSSL error: %s\n", openssl_err ); )

        free( openssl_err );
        return EXIT_FAILURE;
    }

    __debug( printf( "crypto: Packet signature is OK.\n" ); )
    return EXIT_SUCCESS;
}
