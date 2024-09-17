#pragma once

#include "vmlinux.h"
#include <bpf_helpers.h>
#include <bpf_endian.h>

#define DNS_PORT 53

#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

#define OPT_RR_UDP_PAYLOADSIZE 512
#define OPT_RR_UDP_ID 41

#define DNS_CLASS_IN 0x0001

#define A_RECORD_TYPE 0x0001
#define AAAA_RECORD_TYPE 0x001c

// we should set some boundary for qname matching as verifier
// should be glad, see also RFC1034 about dns domain name
// 256, 128, 96, factors
// (1) DEDNS processing
// (2) number of protocols supported ip6ip6, ip6ip4, ip4..
// now we are on 64 without EDNS
// (3) parse qname function 1 - heavier
// (4) DDEBUG
#define MAX_DNS_NAME_LENGTH 48

struct dnshdr {
    uint16_t transaction_id;
    uint8_t rd : 1;      //Recursion desired
    uint8_t tc : 1;      //Truncated
    uint8_t aa : 1;      //Authoritive answer
    uint8_t opcode : 4;  //Opcode
    uint8_t qr : 1;      //Query/response flag
    uint8_t rcode : 4;   //Response code
    uint8_t cd : 1;      //Checking disabled
    uint8_t ad : 1;      //Authenticated data
    uint8_t z : 1;       //Z reserved bit
    uint8_t ra : 1;      //Recursion available
    uint16_t q_count;    //Number of questions
    uint16_t ans_count;  //Number of answer RRs
    uint16_t auth_count; //Number of authority RRs
    uint16_t add_count;  //Number of resource RRs
};

#ifdef EDNS
struct opt_hdr {
    uint8_t qname;
    uint16_t type;
    uint16_t size;
    uint32_t ex_rcode;
    uint16_t rcode_len;
} __attribute__((packed));
#endif

// dns_query is a key to match questions in packet
struct dns_query {
    uint16_t qtype;
    uint16_t qclass;
    char qname[MAX_DNS_NAME_LENGTH];
};

// dns_response is response for dns RR
struct dns_response {
    uint16_t query_pointer;
    uint16_t qtype;
    uint16_t qclass;
    uint32_t ttl;
    uint16_t data_length;
} __attribute__((packed));

// for now, we have each map for each type of RR, e.g.
// we need A and AAAA RR hasmaps and corresponding
// values of different types
struct rr_a {
    // here we have 32bit bytes array
    struct in_addr ip_addr;
    uint32_t ttl;
};

struct rr_aaaa {
    // here we have 128bit bytes array
    struct in6_addr ip_addr;
    uint32_t ttl;
};

// structure to match dst addr6 and addr4
struct dns_daddr6 {
    u32 prefixlen;
    struct in6_addr addr;
};

struct dns_daddr4 {
    u32 prefixlen;
    struct in_addr addr;
};

// see how powerdns parsing headers, T.B.D some more
struct cursor {
    // ip encapsulation proto: could be ip4, ip6
    // ETH_P_IP, ETH_P_IPV6 or 0x0 (no encapsulation)
    uint16_t proto_enc;

    // payload proto: could be ip4, ip6 as
    // ETH_P_IP, ETH_P_IPV6
    uint16_t proto_payload;

    void* pos;
    void* end;

    // dns cursor part detected query length and
    // buf_size of payload packet generated
    int query_length;

    size_t buf_size;
};

struct vlanhdr {
    uint16_t tci;
    uint16_t encap_proto;
};

static inline void cursor_init(struct cursor* c, struct xdp_md* ctx) {
    c->end = (void*)(long)ctx->data_end;
    c->pos = (void*)(long)ctx->data;
}

static int yadns_xdp_rr_a_match(struct xdp_md* ctx, struct dns_query* q, struct rr_a* a, uint16_t rid);
static int yadns_xdp_rr_aaaa_match(struct xdp_md* ctx, struct dns_query* q, struct rr_aaaa* a, uint16_t rid);

static inline int yadns_xdp_qparse(struct xdp_md* ctx, void* query_start, struct dns_query* q);
static inline int yadns_xdp_qparse2(struct xdp_md* ctx, void* query_start, struct dns_query* q);

#ifdef EDNS
static inline int yadns_xdp_optparse(struct xdp_md* ctx, struct dnshdr* dns_hdr, int query_length, struct opt_hdr* opt);
static inline int yadns_xdp_optresponse(struct opt_hdr* opt, char* dns_buffer, size_t* buf_size);
#endif

static int yadns_xdp_dns_packet(struct xdp_md* ctx, struct dnshdr* dns_hdr, struct cursor* c, char* dns_buffer, bool dryrun);

static inline void yadns_xdp_header_response(struct dnshdr* dns_hdr);
static void yadns_xdp_a_response(struct rr_a* a, char* dns_buffer, size_t* buf_size);
static void yadns_xdp_aaaa_response(struct rr_aaaa* a, char* dns_buffer, size_t* buf_size);

static inline void yadns_xdp_response_buf(struct xdp_md* ctx, void* dst, void* src, size_t n);

static inline void swap_mac(uint8_t* src_mac, uint8_t* dst_mac);

// powerdns has some useful declarations for parsing headers [1]
// [1] https://github.com/PowerDNS/pdns/blob/master/contrib/xdp.h

#define PARSE_FUNC_DECLARATION(STRUCT)                              \
    static inline struct STRUCT* parse_##STRUCT(struct cursor* c) { \
        struct STRUCT* ret = c->pos;                                \
        if (c->pos + sizeof(struct STRUCT) > c->end)                \
            return 0;                                               \
        c->pos += sizeof(struct STRUCT);                            \
        return ret;                                                 \
    }

PARSE_FUNC_DECLARATION(ethhdr)
PARSE_FUNC_DECLARATION(iphdr)
PARSE_FUNC_DECLARATION(ipv6hdr)
PARSE_FUNC_DECLARATION(udphdr)
PARSE_FUNC_DECLARATION(dnshdr)
PARSE_FUNC_DECLARATION(vlanhdr)

static inline struct ethhdr* parse_eth(struct cursor* c, uint16_t* eth_proto)
{
    struct ethhdr* eth;

    if (!(eth = parse_ethhdr(c)))
        return 0;

    *eth_proto = eth->h_proto;
    if (*eth_proto == bpf_htons(ETH_P_8021Q) || *eth_proto == bpf_htons(ETH_P_8021AD)) {
#ifdef DEBUG
        bpf_printk("yadns_xdp: VLAN");
#endif

        struct vlanhdr* vlan;

        if (!(vlan = parse_vlanhdr(c)))
            return 0;

        *eth_proto = vlan->encap_proto;
        if (*eth_proto == bpf_htons(ETH_P_8021Q) || *eth_proto == bpf_htons(ETH_P_8021AD)) {
            if (!(vlan = parse_vlanhdr(c)))
                return 0;

            *eth_proto = vlan->encap_proto;
        }
    }

    return eth;
}

// the next block is derived from dnsguard code as is [1]
// [1] https://a.yandex-team.ru/arcadia/noc/dnsguard/bpf/perf.h

/// Performance counter.
struct dg_perf_value {
    u64 counter;
};

/// Computes the base 2 integer logarithm of the specified argument.
static __always_inline u32 dg_bpf_log2(u32 v) {
    u32 r;
    u32 shift;

    r = (v > 0xffff) << 4;
    v >>= r;
    shift = (v > 0xff) << 3;
    v >>= shift;
    r |= shift;
    shift = (v > 0xf) << 2;
    v >>= shift;
    r |= shift;
    shift = (v > 0x3) << 1;
    v >>= shift;
    r |= shift;
    r |= (v >> 1);

    return r;
}

/// Computes the base 2 integer logarithm of the specified argument.
static __always_inline u32 dg_bpf_log2l(u64 v) {
    u32 hi = v >> 32;

    if (hi) {
        return dg_bpf_log2(hi) + 32;
    } else {
        return dg_bpf_log2(v);
    }
}

/// Updates performance counter histogram.
///
/// Buckets are distributed as the following:
/// [0; 1]   -> 0
/// [2; 3]   -> 1
/// [4; 7]   -> 2
/// [8; 15]  -> 3
/// [16; 31] -> 4
/// ...
static __always_inline void dg_histogram_log2_update(void* map, u64 ns) {
    u32 id = dg_bpf_log2l(ns);

    struct dg_perf_value* value = bpf_map_lookup_elem(map, &id);
    if (value != NULL) {
        value->counter++;
    }
}

static __always_inline void dg_metrics_increment(void* map, u32 id) {
    struct dg_perf_value* value = bpf_map_lookup_elem(map, &id);
    if (value != NULL) {
        value->counter++;
    }
}

static __always_inline void dg_metrics_add(void* map, u32 id, u64 v) {
    struct dg_perf_value* value = bpf_map_lookup_elem(map, &id);
    if (value != NULL) {
        value->counter += v;
    }
}

static __always_inline bool dg_config_bool(void* map, u32 id, bool value) {
    u32* val = bpf_map_lookup_elem(map, &id);
    if (val != NULL) {
        return *val == 1;
    }
    return value;
}

/**
 * Return action, exposing the action and input packet to xdpcap hook.
 *
 *   return xdpcap_exit(ctx, &hook, XDP_PASS)
 *
 * is equivalent to:
 *
 *   return XDP_PASS;
 */
__attribute__((__always_inline__)) static inline enum xdp_action xdpcap_exit(struct xdp_md* ctx, void* hook_map, enum xdp_action action) {
    // tail_call
    // Some headers define tail_call (Cilium), others bpf_tail_call (kernel self tests). Use the helper ID directly
    ((int (*)(struct xdp_md*, void*, int))12)(ctx, hook_map, action);
    return action;
}
