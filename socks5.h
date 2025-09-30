#ifndef ENHANCER_SOCKS5_H
#define ENHANCER_SOCKS5_H

#include "common.h"

/* SOCKS5 Protocol Constants */
#define SOCKS5_VERSION 0x05

/* Authentication Methods */
#define SOCKS5_AUTH_NOAUTH 0x00
#define SOCKS5_AUTH_USERPASS 0x02
#define SOCKS5_AUTH_NOACCEPTABLE 0xFF

/* Command Types */
#define SOCKS5_CMD_CONNECT 0x01
#define SOCKS5_CMD_BIND 0x02
#define SOCKS5_CMD_UDP_ASSOCIATE 0x03

/* Address Types */
#define SOCKS5_ATYP_IPV4 0x01
#define SOCKS5_ATYP_DOMAIN 0x03
#define SOCKS5_ATYP_IPV6 0x04

/* Reply Field */
#define SOCKS5_REP_SUCCESS 0x00
#define SOCKS5_REP_GENERAL_FAILURE 0x01
#define SOCKS5_REP_CONN_NOT_ALLOWED 0x02
#define SOCKS5_REP_NETWORK_UNREACHABLE 0x03
#define SOCKS5_REP_HOST_UNREACHABLE 0x04
#define SOCKS5_REP_CONN_REFUSED 0x05
#define SOCKS5_REP_TTL_EXPIRED 0x06
#define SOCKS5_REP_CMD_NOT_SUPPORTED 0x07
#define SOCKS5_REP_ADDR_TYPE_NOT_SUPPORTED 0x08

int socks5_connect(const char *ProxyURL, const char *DestHost, int DestPort);

#endif
