/*
 * Main resource definitions for both client and server application, as
 *  related to the SPA protocol.
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


#ifndef SPA_H
#define SPA_H



#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <openssl/rsa.h>



#define PACKET_BUFFER_SIZE 4096

#define SPA_DEFAULT_BIND_PORT 41937

#define SPA_PACKET_DATA_SIZE 32
#define SPA_PACKET_USERNAME_SIZE 16
#define SPA_PACKET_HASH_SIZE 32
#define SPA_PACKET_MAX_SIGNATURE_SIZE 2048

// Size from the start of a packet that gets hashed.
#define SPA_PACKET_HASHED_SECTION_LEN ( \
    sizeof(spa_packet_t) - sizeof(uint32_t) \
    - SPA_PACKET_MAX_SIGNATURE_SIZE - SPA_PACKET_HASH_SIZE \
)

// Get a max and min on packet length.
//   *** The uint32_t is for the signature_length field.
#define SPA_PACKET_MIN_SIZE ( \
    (sizeof(unsigned char) * SPA_PACKET_DATA_SIZE) \
    + (sizeof(unsigned char) * SPA_PACKET_USERNAME_SIZE) \
    + (sizeof(uint64_t) * 2) \
    + (sizeof(unsigned char) * SPA_PACKET_HASH_SIZE) \
    + sizeof(uint32_t) \
)
#define SPA_PACKET_MAX_SIZE ( \
    SPA_PACKET_MIN_SIZE + SPA_PACKET_MAX_SIGNATURE_SIZE \
)

// Random number generator stuff.
#define IMAX_BITS(m) ((m)/((m)%255+1) / 255%255*8 + 7-86/((m)%255+12))
#define RAND_MAX_WIDTH IMAX_BITS(RAND_MAX)



// Short-hand.
typedef unsigned char BYTE;
#define  ON 1
#define OFF 0



// SPA RESPONSE PACKET DEFINITIONS.

// 0x00 MAJOR MINOR 0xXX (last two can be anything)
#define SPA_SERVER_VERSION 0x00010100
#define SPA_RESPONSE_STRLEN 232

#define SPA_RESPONSE_BASE_SIZE 24

// These could technically be OR'd together to represent multiple failure conditions.
//   But aside from including it in the protocol definition, CSPAUTHD does not do such a thing.
// TODO: Make this perhaps a possibility, with an aggregate failure error string in packet processing.
#define SPA_CODE_BAD_TIMESTAMP     ( 1 << 0 )
#define SPA_CODE_INVALID_USER      ( 1 << 1 )
#define SPA_CODE_HASH_MISMATCH     ( 1 << 2 )
#define SPA_CODE_REPLAYED          ( 1 << 3 )
#define SPA_CODE_INVALID_ACTION    ( 1 << 4 )
#define SPA_CODE_NOT_AUTHORIZED    ( 1 << 5 )
#define SPA_CODE_INVALID_PKEY      ( 1 << 6 )
#define SPA_CODE_INVALID_SIGNATURE ( 1 << 7 )
#define SPA_CODE_SUCCESS           ( 1 << 8 )

// The structure of a response packet.
typedef struct _spa_response_packet_t {
    uint32_t server_version;
    uint16_t response_code;
    uint16_t reserved;
    uint64_t timestamp;
    uint64_t packet_id;
    BYTE response_data[SPA_RESPONSE_STRLEN];
} spa_response_packet_t;



// The structure of an incoming Single Packet Authorization datagram.
typedef struct _spa_packet_t {
    BYTE packet_data[SPA_PACKET_DATA_SIZE];
    BYTE username[SPA_PACKET_USERNAME_SIZE];
    uint64_t client_timestamp;
    uint16_t request_action;
    uint16_t request_option;
    uint32_t __reserved;   //trying to keep nice boundaries
    BYTE packet_hash[SPA_PACKET_HASH_SIZE];
    uint32_t signature_length;
    BYTE packet_signature[SPA_PACKET_MAX_SIGNATURE_SIZE];
} spa_packet_t; //__attribute__((__packed__));

// Wrapper struct for meta-data about an incoming SPA packet.
typedef struct spa_packet_meta_t {
    struct sockaddr_in6 clientaddr;
    spa_packet_t packet;
    uint64_t packet_id;
} spa_packet_meta_t;



#endif   /* SPA_H */
