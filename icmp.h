/* file: icmp.h */
/* Implementation of ICMP echo from scratch for learning purposes */
#ifndef __ICMP__
#define __ICMP__

#include <stdio.h>

typedef unsigned char           u8;
typedef unsigned short          u16;
typedef unsigned int            u32;

/* Maximum Data size */
#define ICMP_MAX_DATA_SIZE      1024

/* Struct defines the ICMP header */
typedef struct icmp_header {
        u8      type;
        u8      code;
        u16     checksum;

        u16     identifier;
        u16     sequence;
} icmp_header;

/* Struct defines the ICMP packet */
typedef struct icmp_packet {
        icmp_header     header;
        char            payload[ICMP_MAX_DATA_SIZE];
} icmp_packet;

#endif //__ICMP__
