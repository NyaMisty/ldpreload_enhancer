#include "socks5.h"
#include "iplist.h"
#include "net.h"
#include <arpa/inet.h>


/*
 * Perform SOCKS5 authentication negotiation
 * Returns: 1 on success, 0 on failure
 */
static int socks5_auth_negotiate(int fd, const char *Username, const char *Password)
{
    char request[3];
    char response[2];
    int auth_method;

    /* Send authentication method selection request */
    request[0] = SOCKS5_VERSION;
    
    if (strvalid(Username) && strvalid(Password))
    {
        /* Support both no auth and username/password */
        request[1] = 2; /* Number of methods */
        request[2] = SOCKS5_AUTH_NOAUTH;
        request[3] = SOCKS5_AUTH_USERPASS;
        if (enhancer_real_write(fd, request, 4) != 4) return(0);
    }
    else
    {
        /* Only support no authentication */
        request[1] = 1; /* Number of methods */
        request[2] = SOCKS5_AUTH_NOAUTH;
        if (enhancer_real_write(fd, request, 3) != 3) return(0);
    }

    /* Receive server's authentication method selection */
    if (read(fd, response, 2) != 2) return(0);
    if (response[0] != SOCKS5_VERSION) return(0);

    auth_method = (unsigned char)response[1];

    if (auth_method == SOCKS5_AUTH_NOACCEPTABLE) return(0);

    /* Handle username/password authentication */
    if (auth_method == SOCKS5_AUTH_USERPASS)
    {
        char auth_request[513];
        char auth_response[2];
        int ulen, plen, pos = 0;

        if (!strvalid(Username) || !strvalid(Password)) return(0);

        ulen = strlen(Username);
        plen = strlen(Password);

        if (ulen > 255 || plen > 255) return(0);

        auth_request[pos++] = 0x01; /* Username/password auth version */
        auth_request[pos++] = (char)ulen;
        memcpy(auth_request + pos, Username, ulen);
        pos += ulen;
        auth_request[pos++] = (char)plen;
        memcpy(auth_request + pos, Password, plen);
        pos += plen;

        if (enhancer_real_write(fd, auth_request, pos) != pos) return(0);

        if (read(fd, auth_response, 2) != 2) return(0);
        if (auth_response[0] != 0x01 || auth_response[1] != 0x00) return(0);
    }

    return(1);
}


/*
 * Send SOCKS5 connection request
 * Returns: 1 on success, 0 on failure
 */
static int socks5_request(int fd, const char *DestHost, int DestPort)
{
    char request[512];
    struct in_addr ipv4_addr;
    int pos = 0;
    int host_len;

    if (fd == -1) return(0);

    /* Build SOCKS5 request */
    request[pos++] = SOCKS5_VERSION;
    request[pos++] = SOCKS5_CMD_CONNECT;
    request[pos++] = 0x00; /* Reserved */

    /* Determine address type and encode destination */
    if (inet_aton(DestHost, &ipv4_addr))
    {
        /* IPv4 address */
        request[pos++] = SOCKS5_ATYP_IPV4;
        memcpy(request + pos, &ipv4_addr.s_addr, 4);
        pos += 4;
    }
    else
    {
        /* Domain name */
        host_len = strlen(DestHost);
        if (host_len > 255) return(0);

        request[pos++] = SOCKS5_ATYP_DOMAIN;
        request[pos++] = (char)host_len;
        memcpy(request + pos, DestHost, host_len);
        pos += host_len;
    }

    /* Add port (network byte order) */
    *(uint16_t *)(request + pos) = htons((uint16_t)DestPort);
    pos += 2;

    /* Send request */
    if (enhancer_real_write(fd, request, pos) != pos) return(0);

    return(1);
}


/*
 * Receive SOCKS5 connection reply
 * Returns: 1 on success, 0 on failure
 */
static int socks5_reply(int fd)
{
    char response[512];
    int addr_len = 0;
    int total_len;
    unsigned char atyp;

    /* Read fixed part of response: VER, REP, RSV, ATYP */
    if (read(fd, response, 4) != 4) return(0);

    /* Check version */
    if ((unsigned char)response[0] != SOCKS5_VERSION) return(0);

    /* Check reply code */
    if ((unsigned char)response[1] != SOCKS5_REP_SUCCESS) return(0);

    /* Parse address type to determine how much more to read */
    atyp = (unsigned char)response[3];

    switch (atyp)
    {
    case SOCKS5_ATYP_IPV4:
        addr_len = 4;
        break;
    case SOCKS5_ATYP_IPV6:
        addr_len = 16;
        break;
    case SOCKS5_ATYP_DOMAIN:
        /* Read domain name length */
        if (read(fd, response + 4, 1) != 1) return(0);
        addr_len = (unsigned char)response[4] + 1; /* +1 for length byte itself */
        break;
    default:
        return(0);
    }

    /* Read address + port (2 bytes) */
    total_len = (atyp == SOCKS5_ATYP_DOMAIN) ? addr_len - 1 + 2 : addr_len + 2;
    
    if (atyp == SOCKS5_ATYP_DOMAIN)
    {
        /* Already read length byte, read domain name + port */
        if (read(fd, response + 5, total_len) != total_len) return(0);
    }
    else
    {
        /* Read address + port */
        if (read(fd, response + 4, total_len) != total_len) return(0);
    }

    return(1);
}


/*
 * Connect to destination through SOCKS5 proxy
 * ProxyURL format: socks5://[user:pass@]host:port
 * Returns: file descriptor on success, -1 on failure
 */
int socks5_connect(const char *ProxyURL, const char *DestHost, int DestPort)
{
    char *Username=NULL, *Password=NULL;
    const char *ptr;
    int fd;

    if (!DestHost) return(-1);

    /* Parse authentication credentials if present */
    if (strchr(ProxyURL, '@'))
    {
        ptr=enhancer_strtok(ProxyURL, ":", &Username);
        ptr=enhancer_strtok(ptr, "@", &Password);
    }

    /* Connect to SOCKS5 proxy */
    fd=net_connect(ProxyURL);
    if (fd > -1)
    {
        /* Resolve hostname if needed */
        ptr=enhancer_iplist_get(DestHost);
        if (!strvalid(ptr)) ptr=DestHost;

        /* Perform SOCKS5 handshake */
        if (
            (!socks5_auth_negotiate(fd, Username, Password)) ||
            (!socks5_request(fd, ptr, DestPort)) ||
            (!socks5_reply(fd))
        )
        {
            close(fd);
            fd=-1;
        }
    }

    destroy(Username);
    destroy(Password);
    return(fd);
}
