//
// yadns_xdp implements xdp dns response generation for matched
// query dns qname, qtype. Looking up in yadns_xdp_rr_a bpf map with
// a key of qtype, qclass and qname as a struct. This code
// uses bpf_xdp_adjust_tail() function to grow xdp packet buffer,
// ip4 csum update, ip6 udp csum update.
//
// HEADSUP: PoC
//

#include "yadns-xdp.bpf.h"

// By default we always PASS packet further if we have
// some errors or conditions fails. Expecting that such
// packets are processed by dns server later
#define DEFAULT_ACTION XDP_PASS

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dns_query);
    __type(value, struct rr_a);
    __uint(max_entries, 32468000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} yadns_xdp_rr_a SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dns_query);
    __type(value, struct rr_aaaa);
    __uint(max_entries, 32468000);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} yadns_xdp_rr_aaaa SEC(".maps");

// Two maps for v6 and v4 to match dest addr of
// services we should process
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct dns_daddr6);
    __type(value, uint8_t);
    __uint(max_entries, 128);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} daddr6_pass SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct dns_daddr4);
    __type(value, uint8_t);
    __uint(max_entries, 128);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} daddr4_pass SEC(".maps");

// response flag selection, using in AA (authority) or
// (RD) recursion variants
static volatile const bool yadns_xdp_resp_flag_aa = false;
static volatile const bool yadns_xdp_resp_flag_rd = false;
static volatile const bool yadns_xdp_resp_flag_mbz = false;

// random ttl switch (could be used in AA responses)
static volatile const bool yadns_xdp_resp_random_ttl = false;

// gathering bpf metrics: rps, times histograms, avg, max, min
static volatile const bool yadns_xdp_bpf_metrics_enabled = true;
static volatile const bool yadns_xdp_bpf_xdpcap_enabled = true;
static volatile const bool yadns_xdp_bpf_dryrun = false;

#define JERICO_RUNTIME_CONFIG_DYRUN 0

// map to configure bpf in runtime
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 16);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} yadns_xdp_runtime_config SEC(".maps");

// The key is the log2 from elapsed time.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct dg_perf_value);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} yadns_xdp_perf SEC(".maps");

// counters for packets RX, TX and PASS
#define JERICO_METRICS_PACKETS_RX 0
#define JERICO_METRICS_PACKETS_TX 1
#define JERICO_METRICS_PACKETS_PASS 2
#define JERICO_METRICS_PACKETS_ERROR 3

// need to have min/avg/max time processing
// not onlt histogram
#define JERICO_METRICS_TIME_MIN 4
#define JERICO_METRICS_TIME_MAX 5
#define JERICO_METRICS_TIME_SUM 6
#define JERICO_METRICS_TIME_CNT 7

// please note we have the limit of MAX
#define JERICO_METRICS_MAX 63

// we use simple array for metrics (assuming uint64 as value)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct dg_perf_value);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} yadns_xdp_metrics SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 5);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdpcap_hook SEC(".maps");

// as usually we should have some boundary for loops to
// satisfy verifier
#define MAX_UDP_SIZE 1480

// max number of checksum overflow check
#define MAX_UDP6_CHECKSUM_OVERFLOW 4

#define MAX_DNS_PAYLOAD 128

// calculating udp checksum for ip6 ip header and udp header and payload
static inline __u16 udp6csum(struct ipv6hdr* iph, struct udphdr* udph, void* data_end, uint8_t len) {
    // csum could be more than 16bit as sum of 16bit numbers
    // in the end we round it to 16bit again
    __u32 csum = 0;

    __u16* buf = (void*)udph;
    __u16* ipbuf = (void*)(&iph->saddr);

    // calculating sum for pseudo-header numbers:
    // IP addresses saddr and daddr, nexthdr (proto)
    // and payload length
    for (int i = 0; i < len / 2; i++) {
        __u16 word = ipbuf[i];
#ifdef DEBUG
        bpf_printk("yadns_xdp: (headers) csum: destination: i:'%d' w:'0x%04x", i, word);
#endif
        csum += word;
    }

    // adding length (the same as in ip header)
    csum += udph->len;

    // nexthdr is a byte need to flip it in word
    csum += (__u16)iph->nexthdr << 8;

    // udpheader and payload + one case for odd number
    // of bytes, we need add the last byte. Here, again, we should
    // satisfy verifer and set static MAX_UDP_SIZE constant
    for (int i = 0; i < MAX_UDP_SIZE; i += 2) {
        if ((void*)(buf + 1) > data_end)
            break;

        __u16 word = *buf;
        csum += word;
        buf++;
    }

    // adding one more byte if data is not word aligned
    if ((void*)buf + 1 <= data_end) {
        // T.B.D. checking if this section is executed and
        // last byte is not "0"
        csum += *(__u8*)buf;
    }

    csum = (csum & 0xFFFF) + (csum >> 16);
    for (int i = 0; i < MAX_UDP6_CHECKSUM_OVERFLOW; i++) {
        if (!(csum >> 16)) {
            break;
        }
        csum = (csum & 0xFFFF) + (csum >> 16);
    }
    csum = ~csum;

    if ((csum & 0xFFFF) == 0) {
        csum = 0xFFFF;
    }

#ifdef DEBUG
    bpf_printk("yadns_xdp: udp6 checksum: ports:'%d' '%d' '0x%0x", udph->source, udph->dest, csum);
#endif
    return csum;
}

// for ip4 we need update ip checksum for ip4 header, as we have [1],
// setting calculated csum as a pointer to value
// [1]  https://datatracker.ietf.org/doc/html/rfc1071
static inline void ip4csum(void* data, int len, uint16_t* csum) {
    uint32_t sum = 0;
    for (int i = 0; i < len; i += 2) {
        uint16_t val;
        if (data + i == csum) {
            val = 0;
        } else {
            val = *(uint16_t*)(data + i);
        }
        sum += val;
    }

    uint16_t overflow = sum >> 16;
    sum &= 0xFFFF;
    sum += overflow;

    sum += (sum >> 16);
    sum &= 0xFFFF;

    uint16_t chk = sum ^ 0xFFFF;

#ifdef DEBUG
    bpf_printk("yadns_xdp: ip4 checksum: '0x%x'", chk);
#endif

    *csum = chk;
}

static int yadns_xdp_ipip_pop(struct xdp_md* ctx, struct cursor* c) {
    // as we have no any encapsulation we could not
    // skip any header
    if (c->proto_enc == 0)
        return 0;

    // for ip6ip4 we also should not skip header
    if ((c->proto_enc == ETH_P_IPV6) && (c->proto_payload == ETH_P_IP))
        return 0;

    void* data = (void*)(unsigned long)ctx->data;
    void* data_end = (void*)(long)ctx->data_end;

    struct ethhdr eth_cpy;
    struct ethhdr* eth = data;

    if ((void*)(eth + 1) > data_end)
        return -1;

    // T.B.D. if we have vlan tags on ethernet we
    // need respect vlan tag headers, at least one
    // assumption should be strict we have only one
    // possible ip encapsulation, not more

    int size = 0;
    switch (c->proto_enc) {
        case ETH_P_IPV6:
            size = (int)sizeof(struct ipv6hdr);
            break;
        case ETH_P_IP:
            size = (int)sizeof(struct iphdr);
            break;
    }

    __builtin_memcpy(&eth_cpy, eth, sizeof(eth_cpy));

    if (bpf_xdp_adjust_head(ctx, size))
        return -1;

    // context is changed need recheck again
    eth = (void*)(unsigned long)ctx->data;
    data_end = (void*)(long)ctx->data_end;
    if ((void*)(eth + 1) > data_end)
        return -1;

    __builtin_memcpy(eth, &eth_cpy, sizeof(*eth));

    return 0;
}

// default decap as ip6 "2a02:6b8:0:3400::aaaa", native order here
#define IN6ADDR_DEFAULT_DECAP                                                     \
    {                                                                             \
        {                                                                         \
            { 0x2a, 0x2, 0x6, 0xb8, 0, 0, 0x34, 0, 0, 0, 0, 0, 0, 0, 0xaa, 0xaa } \
        }                                                                         \
    }

struct in6_addr decap_addr = IN6ADDR_DEFAULT_DECAP;

static void yadns_xdp_dumpv6(struct ipv6hdr* ipv6) {
    __u16* sbuf = (void*)(&ipv6->saddr);
    for (int i = 0; i < 16; i++) {
        uint16_t word = sbuf[i];
        bpf_printk("yadns_xdp: addr i:'%d' w:'0x%04x", i, word);
    }
}

// replying with ipv4 packet forming from dns_buffer
static int yadns_xdp_response_v4(struct xdp_md* ctx, struct cursor* c, char* dns_buffer) {
    // if we have ip encapsulation, need to squeze packet
    if (yadns_xdp_ipip_pop(ctx, c) < 0) {
        return -1;
    }

    void* data = (void*)(unsigned long)ctx->data;
    void* data_end = (void*)(unsigned long)ctx->data_end;

    uint16_t encap_offset = sizeof(struct ethhdr) + sizeof(struct iphdr);

    // assuming ip6 packet and ip4 in stack
    if (c->proto_enc == ETH_P_IPV6)
        encap_offset += sizeof(struct ipv6hdr);

    // copying bytes from our temporary buffer to packet buffer
    yadns_xdp_response_buf(ctx, data + encap_offset + sizeof(struct udphdr) + sizeof(struct dnshdr) + c->query_length,
                           &dns_buffer[0], c->buf_size);

    struct ethhdr* eth = data;
    struct iphdr* ip = data + encap_offset - sizeof(struct iphdr);
    struct udphdr* udp = data + encap_offset;

    // something could change either
    if (data + encap_offset + sizeof(struct udphdr) > data_end) {
        return -1;
    }

    // adjusting udp and IP header length
    uint16_t iplen = (data_end - data) - encap_offset + sizeof(struct iphdr);
    uint16_t udplen = (data_end - data) - encap_offset;
    ip->tot_len = bpf_htons(iplen);
    udp->len = bpf_htons(udplen);

    uint32_t src_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = src_ip;

    udp->check = 0;

    uint16_t tmp_src = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_src;

    // do we need udp checks for ip4? algo is the same
    // as in ip6 but need some minor changes
    //udp->check = udpcsum(ip, udp, data_end, 8);

    ip4csum(ip, sizeof(struct iphdr), &ip->check);

    if (c->proto_enc == ETH_P_IPV6) {
        // we need swap ipv6 addresses in external ipv6 packet
        // and set destination addr to ip6->ip4 decap, should
        // be configured via map
        uint16_t payloadlen = (data_end - data) - sizeof(struct ethhdr) - sizeof(struct ipv6hdr);

        struct ipv6hdr* ipv6 = data + sizeof(struct ethhdr);
        struct in6_addr swap_ipv6 = ipv6->daddr;
        ipv6->daddr = ipv6->saddr;
        ipv6->saddr = swap_ipv6;

        // setting default decap
        ipv6->daddr = decap_addr;

        ipv6->payload_len = bpf_htons(payloadlen);

        yadns_xdp_dumpv6(ipv6);

#ifdef DEBUG
        bpf_printk("yadns_xdp: ip6ip4 encapsulation to decap, tun payload:'%d' ip len:'%d' udp len:'%d'", payloadlen, iplen, udplen);
#endif
    }

    swap_mac((uint8_t*)eth->h_source, (uint8_t*)eth->h_dest);

    return 0;
}

// replying with ipv6 packet forming from dns_buffer
static int yadns_xdp_response_v6(struct xdp_md* ctx, struct cursor* c, char* dns_buffer) {
    // if we have ip encapsulation, need to squeze packet
    if (yadns_xdp_ipip_pop(ctx, c) < 0) {
        return -1;
    }

    void* data = (void*)(unsigned long)ctx->data;
    void* data_end = (void*)(unsigned long)ctx->data_end;

    // copying bytes from our temporary buffer to packet buffer
    yadns_xdp_response_buf(ctx, data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr) + sizeof(struct dnshdr) + c->query_length,
                           &dns_buffer[0], c->buf_size);

    struct ethhdr* eth = data;
    struct ipv6hdr* ipv6 = data + sizeof(struct ethhdr);
    struct udphdr* udp = data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr);

    // something could change either
    if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr) > data_end) {
        return -1;
    }

    // adjusting udp and IP header length
    uint16_t udplen = (data_end - data) - sizeof(struct ethhdr) - sizeof(struct ipv6hdr);

    ipv6->payload_len = bpf_htons(udplen);
    udp->len = bpf_htons(udplen);

    // swap src/dest IP6 addresses
    struct in6_addr swap_ipv6 = ipv6->daddr;
    ipv6->daddr = ipv6->saddr;
    ipv6->saddr = swap_ipv6;

    uint16_t tmp_src = udp->source;
    udp->source = udp->dest;
    udp->dest = tmp_src;

    udp->check = 0;

    // recalculating checksum after ether, source and port changes
    udp->check = udp6csum(ipv6, udp, data_end, 32);

    swap_mac((uint8_t*)eth->h_source, (uint8_t*)eth->h_dest);

    return 0;
}

// processing dns packet from udp level and down
static int yadns_xdp_dns_process(struct xdp_md* ctx, struct cursor* c, bool dryrun) {
    struct udphdr* udp;
    struct dnshdr* dns_hdr;

    if (!(udp = parse_udphdr(c)) || udp->dest != bpf_htons(DNS_PORT)) {
        return DEFAULT_ACTION;
    }

    // check that we have a DNS packet
    if (!(dns_hdr = parse_dnshdr(c))) {
        return DEFAULT_ACTION;
    }

    if (yadns_xdp_bpf_metrics_enabled) {
        dg_metrics_increment(&yadns_xdp_metrics, JERICO_METRICS_PACKETS_RX);
    }

    // We have dns buffer to from dns response. Please check
    // sizes we should use. Sizes are used in EDNS size, MTU
    // packet and udp checksum updates
    char dns_buffer[MAX_DNS_PAYLOAD];

    if (yadns_xdp_dns_packet(ctx, dns_hdr, c, dns_buffer, dryrun) == XDP_TX) {
        // at least now only ip4 is responded
        switch (c->proto_payload) {
            case ETH_P_IP:
                // we have dns_buffer established, buf_size set, assuming
                // that we have here ip4 proto
                if (yadns_xdp_response_v4(ctx, c, &dns_buffer[0]) < 0) {
                    // something went wrong, fallback to default action
                    // hope nobody died
                    if (yadns_xdp_bpf_metrics_enabled) {
                        dg_metrics_increment(&yadns_xdp_metrics, JERICO_METRICS_PACKETS_ERROR);
                    }
                    return DEFAULT_ACTION;
                }
                if (yadns_xdp_bpf_metrics_enabled) {
                    dg_metrics_increment(&yadns_xdp_metrics, JERICO_METRICS_PACKETS_TX);
                }
                return XDP_TX;
                break;
            case ETH_P_IPV6:
                // we have generated data push back as ipv6
                if (yadns_xdp_response_v6(ctx, c, &dns_buffer[0]) < 0) {
                    if (yadns_xdp_bpf_metrics_enabled) {
                        dg_metrics_increment(&yadns_xdp_metrics, JERICO_METRICS_PACKETS_ERROR);
                    }
                    return DEFAULT_ACTION;
                }
                if (yadns_xdp_bpf_metrics_enabled) {
                    dg_metrics_increment(&yadns_xdp_metrics, JERICO_METRICS_PACKETS_TX);
                }
                return XDP_TX;
                break;
        }
    }

    return DEFAULT_ACTION;
}

// parsing and forming response for dns, we expect that all headers
// already skipping out, eth, vlan?, ip4/ip6, ipip?
static int yadns_xdp_dns_packet(struct xdp_md* ctx, struct dnshdr* dns_hdr, struct cursor* c, char* dns_buffer, bool dryrun) {
    // assuming standard query in dns header
    if (dns_hdr->qr == 0 && dns_hdr->opcode == 0) {
        uint16_t rid = bpf_ntohs(dns_hdr->transaction_id);
        void* query_start = (void*)dns_hdr + sizeof(struct dnshdr);

        // expecting that dns request contains only one question, if
        // we have several we could skip it?
        struct dns_query q;

        c->query_length = 0;
#ifdef QPARSE2
        c->query_length = yadns_xdp_qparse2(ctx, query_start, &q);
#else
        c->query_length = yadns_xdp_qparse(ctx, query_start, &q);
#endif
        if (c->query_length < 1) {
            return DEFAULT_ACTION;
        }

        // checking a query data, if we need multiple answers we need
        // modify key adding an index
#ifdef DEBUG
        bpf_printk("yadns_xdp: dns record type: %i", q.qtype);
        bpf_printk("yadns_xdp: dns class: %i", q.qclass);
        bpf_printk("yadns_xdp: dns qname: %s", q.qname);
        bpf_printk("yadns_xdp: c->query_length: %d", c->query_length);
        bpf_printk("yadns_xdp: dns transaction id:'%u'", rid);
#endif

        c->buf_size = 0;

        switch (q.qtype) {
            case A_RECORD_TYPE: {
                struct rr_a a_record;
                if (yadns_xdp_rr_a_match(ctx, &q, &a_record, rid) < 0) {
                    if (yadns_xdp_bpf_metrics_enabled) {
                        dg_metrics_increment(&yadns_xdp_metrics, JERICO_METRICS_PACKETS_PASS);
                    }

                    return DEFAULT_ACTION;
                }

                if (dryrun) {
                    // skipping any modifications of packets but increment for TX
                    if (yadns_xdp_bpf_metrics_enabled) {
                        dg_metrics_increment(&yadns_xdp_metrics, JERICO_METRICS_PACKETS_TX);
                    }
                    return DEFAULT_ACTION;
                }

                yadns_xdp_header_response(dns_hdr);
                yadns_xdp_a_response(&a_record, &dns_buffer[c->buf_size], &c->buf_size);

            } break;
            case AAAA_RECORD_TYPE: {
                struct rr_aaaa aaaa_record;
                if (yadns_xdp_rr_aaaa_match(ctx, &q, &aaaa_record, rid) < 0) {
                    if (yadns_xdp_bpf_metrics_enabled) {
                        dg_metrics_increment(&yadns_xdp_metrics, JERICO_METRICS_PACKETS_PASS);
                    }

                    return DEFAULT_ACTION;
                }

                if (dryrun) {
                    // skipping any modifications of packets but increment for TX
                    if (yadns_xdp_bpf_metrics_enabled) {
                        dg_metrics_increment(&yadns_xdp_metrics, JERICO_METRICS_PACKETS_TX);
                    }
                    return DEFAULT_ACTION;
                }

                yadns_xdp_header_response(dns_hdr);
                yadns_xdp_aaaa_response(&aaaa_record, &dns_buffer[c->buf_size], &c->buf_size);
            } break;
            default:
                return DEFAULT_ACTION;
        }

#ifdef EDNS
        // edns could contain some useful data, trying to parse it
        // and add some useful response, please beware about EDNS0 sizes
        if (dns_hdr->add_count > 0) {
            struct opt_hdr ar;
            if (yadns_xdp_optparse(ctx, dns_hdr, c->query_length, &ar) != -1) {
                // adding AR as OPT response to temporary buffer
                yadns_xdp_optresponse(&ar, &dns_buffer[c->buf_size], &c->buf_size);
            }
        }
#endif

        // response bytes beyond the header
        void* answer_start = (void*)dns_hdr + sizeof(struct dnshdr) + c->query_length;

        // how much packet should be increased
        int tailadjust = answer_start + c->buf_size - c->end;

#ifdef DEBUG
        bpf_printk("yadns_xdp: c.buf_size:'%d' c.query_length:'%d' tail:'%d'", c->buf_size, c->query_length, tailadjust);
#endif

        // adjusting packet to fill formed before response
        if (bpf_xdp_adjust_tail(ctx, tailadjust) < 0) {
            bpf_printk("yadns_xdp: error on adjust tail");
            return DEFAULT_ACTION;
        }

        // from this point we could push data on wire
        return XDP_TX;
    }

    return DEFAULT_ACTION;
}

static uint32_t yadns_xdp_ttl(uint32_t ttl, uint16_t rid) {
    if (yadns_xdp_resp_random_ttl) {
        // detecting random TTL as a function of
        // modulo request id w.r.t to original TTL
        uint32_t l = ttl / 2;
        return (rid % l) + l;
    }
    return ttl;
}

// matching qname for record a (should we have a general function to
// match all types we interested in: A, AAAA, CNAME, NS? or just have
// them all different
static int yadns_xdp_rr_a_match(struct xdp_md* ctx, struct dns_query* q, struct rr_a* a, uint16_t rid) {
    struct rr_a* rr = bpf_map_lookup_elem(&yadns_xdp_rr_a, q);
    if (rr > 0) {
        a->ip_addr = rr->ip_addr;
        a->ttl = yadns_xdp_ttl(rr->ttl, rid);
        return 0;
    }
    return -1;
}

static int yadns_xdp_rr_aaaa_match(struct xdp_md* ctx, struct dns_query* q, struct rr_aaaa* a, uint16_t rid) {
    struct rr_aaaa* rr = bpf_map_lookup_elem(&yadns_xdp_rr_aaaa, q);
    if (rr > 0) {
        a->ip_addr = rr->ip_addr;
        a->ttl = yadns_xdp_ttl(rr->ttl, rid);

#ifdef DEBUG
        bpf_printk("yadns_xdp: dns AAAA query found qname:'%s' qtype:'%i'", q->qname, q->qtype);
        for (int i = 0; i < 4; i++) {
            uint32_t word = a->ip_addr.in6_u.u6_addr32[i];
            bpf_printk("yadns_xdp: AAAA addr i:'%d' w:'0x%08x", i, word);
        }

#endif
        return 0;
    }
    return -1;
}

#ifdef QPARSE2
// this version is less complicated and less variative then yadns_xdp_qparse
static inline int yadns_xdp_qparse2(struct xdp_md* ctx, void* query_start, struct dns_query* q) {
    uint8_t qname_byte;
    int length = 0;
    int namepos = 0;

    void* start = query_start;

    __builtin_memset(&q->qname[0], 0, sizeof(q->qname));
    q->qtype = 0;
    q->qclass = DNS_CLASS_IN;

    for (int16_t i = 0; i < MAX_DNS_NAME_LENGTH; i++) {
        bpf_probe_read_kernel(&qname_byte, sizeof(qname_byte), start);
        start++;
        if (length == 0) {
            if (qname_byte == 0 || qname_byte > 63) {
                break;
            }
            length += qname_byte;
        } else {
            length--;
        }
        q->qname[i] = qname_byte;
        namepos++;
    }

    uint16_t qtype;
    bpf_probe_read_kernel(&qtype, sizeof(q->qtype), start);
    q->qtype = bpf_htons(qtype);

    return namepos + 1 + 2 + 2;
}
#else
// parsing a dns query detecting only A record type at least for now
static inline int yadns_xdp_qparse(struct xdp_md* ctx, void* query_start, struct dns_query* q) {
    void* data_end = (void*)(long)ctx->data_end;

    void* cursor = query_start;
    int namepos = 0;

    // setting qname to zero memory, also satisfying verifer about
    // name as it is used in bpf map lookup function
    __builtin_memset(&q->qname[0], 0, sizeof(q->qname));

    q->qtype = 0;
    q->qclass = DNS_CLASS_IN;

    // in bounded loop we parse packet starting from query name
    // position till the zero symbol foud
    for (uint16_t i = 0; i < MAX_DNS_NAME_LENGTH; i++) {
        // some verifier-satisfy check not to move cursor
        // out of packet data_end position
        if (cursor + 1 > data_end) {
            break;
        }

        if (*(char*)(cursor) == 0) {
            // in the end we have qclass and qtype plus
            // 1byte zero-symbol
            if (cursor + 5 > data_end) {
                // not sure what to do, could we have just to skip
                // dns packet is incorrect

            } else {
                q->qtype = bpf_htons(*(uint16_t*)(cursor + 1));
                q->qclass = bpf_htons(*(uint16_t*)(cursor + 3));
            }
            // again we have qclass, qtype and zero symbol
            return namepos + 1 + 2 + 2;
        }

        q->qname[namepos] = *(char*)(cursor);
        namepos++;
        cursor++;
    }

    return -1;
}
#endif

#ifdef EDNS

// some rrsets could also be present as OPT EDNS additional rrsets with
// COOKIE or some other information, SUBNET CLIENT data, we need parse it
static inline int yadns_xdp_optparse(struct xdp_md* ctx, struct dnshdr* dns_hdr, int query_length, struct opt_hdr* opt) {
    void* data_end = (void*)(long)ctx->data_end;

    // as we have OPT AR rrsets located after the end of QUESTION
    opt = (void*)dns_hdr + query_length + sizeof(struct dns_response);

    // simple check for data end structure
    if ((void*)opt + sizeof(struct opt_hdr) > data_end) {
        return -1;
    }
    return 0;
}

// need to response with OPT header EDNS udp payload size, at least
// now we have here static value of, see also RFC6891
static inline int yadns_xdp_optresponse(struct opt_hdr* opt, char* dns_buffer, size_t* buf_size) {
    if (opt->type == bpf_htons(OPT_RR_UDP_ID)) {
        struct opt_hdr* opt_response = (struct opt_hdr*)&dns_buffer[0];

        // T.B.D. we here should say about udp payload size we
        // expect and which additional records we serve
        // SUBNET CLIENT?

        opt_response->qname = 0;
        opt_response->type = bpf_htons(OPT_RR_UDP_ID);
        opt_response->size = bpf_htons(OPT_RR_UDP_PAYLOADSIZE);
        opt_response->ex_rcode = 0;
        opt_response->rcode_len = 0;

        *buf_size += sizeof(struct opt_hdr);

        return 0;
    }

    return -1;
}
#endif

// modifying dns response header to set it corresponding flags, see
// also AA, RA flags
static inline void yadns_xdp_header_response(struct dnshdr* dns_hdr) {
    // query response should have QR flag set to 1
    dns_hdr->qr = 1;

    // we do not have DNSSEC validation
    dns_hdr->ad = 0;

    // we do not process TC in any way
    dns_hdr->tc = 0;

    // rd and cd flags should be copied from request

    if (yadns_xdp_resp_flag_mbz) {
        // in order to destinguish responses from xdp
        // set this MBZ flag also (I hope it is not used)
        dns_hdr->z = 1;
    }

    if (yadns_xdp_resp_flag_aa) {
        // assuming authority responses with no
        // recurson allowed
        dns_hdr->aa = 1;
        dns_hdr->ra = 0;

        // rd flag should be copied from request
        // also as cd
    }

    if (yadns_xdp_resp_flag_rd) {
        // no actual authority responses, recursion
        // is always available
        dns_hdr->aa = 0;
        dns_hdr->ra = 1;

        // rd is set in request. we do not have here
        // only one case processing if rd in request
        // is **not** set. In such cases we should
        // generate REFUSE response but we cannot do such
        // responses from bpf (at least now)
    }

    // setting additinal count to zero, and
    // adding one if EDNS OPT RR is enabled
    dns_hdr->add_count = 0;

#ifdef EDNS
    dns_hdr->add_count = 1;
#endif

    //  T.B.D. number of answers to reply (it surely could be more than 1
    //  for responses in multiple cache answers)
    dns_hdr->ans_count = bpf_htons(1);
}

// creating a response structure as (for now) A response
static void yadns_xdp_a_response(struct rr_a* a, char* dns_buffer, size_t* buf_size) {
    // we have here only one response for one question, so
    // all things should be not too complicated. The only one
    // thing to mention - query pointer (it is used as 0xc00c)
    struct dns_response* response = (struct dns_response*)&dns_buffer[0];

    // here we have always 12byte offset as dnsheader is 3*4bytes
    response->query_pointer = bpf_htons(0xc00c);

    // T.B.D. of course it should be used as a parameter
    response->qtype = bpf_htons(A_RECORD_TYPE);
    response->qclass = bpf_htons(DNS_CLASS_IN);
    response->ttl = bpf_htonl(a->ttl);
    response->data_length = bpf_htons((uint16_t)sizeof(struct in_addr));

    *buf_size += sizeof(struct dns_response);

    // for A record we have IP4 address to copy as dns RR "payload"
    __builtin_memcpy(&dns_buffer[*buf_size], &a->ip_addr, sizeof(struct in_addr));
    *buf_size += sizeof(struct in_addr);
}

// creating aaaa response structure as (for now) A response
static void yadns_xdp_aaaa_response(struct rr_aaaa* a, char* dns_buffer, size_t* buf_size) {
    struct dns_response* response = (struct dns_response*)&dns_buffer[0];

    // pointer to qname back to 12 bytes
    response->query_pointer = bpf_htons(0xc00c);

    response->qtype = bpf_htons(AAAA_RECORD_TYPE);
    response->qclass = bpf_htons(DNS_CLASS_IN);
    response->ttl = bpf_htonl(a->ttl);
    response->data_length = bpf_htons((uint16_t)sizeof(struct in6_addr));

    *buf_size += sizeof(struct dns_response);

    __builtin_memcpy(&dns_buffer[*buf_size], &a->ip_addr, sizeof(struct in6_addr));
    *buf_size += sizeof(struct in6_addr);
}

// for some reason we could have exaclty number of bytes to copy as A record
// response with OPT or without OPT RR, resulting in 27 or 16 bytes, explicitly
// use it in case (as __builtin_memcpy supports only static sizes)
#define BYTES_RR_A_OPTRR 27
#define BYTES_RR_A 16

#define BYTES_RR_AAAA 28
#define BYTES_RR_AAAA_OPTRR 39

static inline void yadns_xdp_response_buf(struct xdp_md* ctx, void* dst, void* src, size_t n) {
    // as always we need bounday check
    if ((void*)(long)ctx->data_end >= dst + n) {
#ifdef DEBUG
        bpf_printk("yadns_xdp: response buf AAAA size:'%d'", n);
#endif

        char* cdst = dst;
        char* csrc = src;
        switch (n) {
            case BYTES_RR_A:
                __builtin_memcpy(cdst, csrc, BYTES_RR_A);
                break;
            case BYTES_RR_AAAA:
                __builtin_memcpy(cdst, csrc, BYTES_RR_AAAA);
                break;
            case BYTES_RR_AAAA_OPTRR:
                __builtin_memcpy(cdst, csrc, BYTES_RR_AAAA_OPTRR);
                break;
            case BYTES_RR_A_OPTRR:
                __builtin_memcpy(cdst, csrc, BYTES_RR_A_OPTRR);
                break;
        }
    }
}

static inline void swap_mac(uint8_t* src_mac, uint8_t* dst_mac) {
    for (uint8_t i = 0; i < 6; i++) {
        uint8_t tmp_src;
        tmp_src = *(src_mac + i);
        *(src_mac + i) = *(dst_mac + i);
        *(dst_mac + i) = tmp_src;
#ifdef DEBUG
        bpf_printk("yadns_xdp: swap mac i:'%d' c:'%x' <-> '%x'", i, tmp_src, *(src_mac + i));
#endif
    }
}

static inline bool yadns_xdp_dstaddr6(struct in6_addr* addr) {
    struct dns_daddr6 key = {
        .prefixlen = 128,
        .addr = *addr,
    };
    return bpf_map_lookup_elem(&daddr6_pass, &key) != NULL;
}

static inline bool yadns_xdp_dstaddr4(uint32_t addr) {
    struct in_addr addr4 = {
        .s_addr = addr,
    };
    struct dns_daddr4 key = {
        .prefixlen = 32,
        .addr = addr4,
    };

    return bpf_map_lookup_elem(&daddr4_pass, &key) != NULL;
}

static inline void yadns_xdp_metrics_update(u64 t) {
    u32 maxid = JERICO_METRICS_TIME_MAX;
    struct dg_perf_value* max = bpf_map_lookup_elem(&yadns_xdp_metrics, &maxid);
    if (max != NULL) {
        if (max->counter < t) {
            max->counter = t;
        }
    }

    u32 sumid = JERICO_METRICS_TIME_SUM;
    struct dg_perf_value* sum = bpf_map_lookup_elem(&yadns_xdp_metrics, &sumid);
    if (sum != NULL) {
        sum->counter += t;
    }

    u32 cntid = JERICO_METRICS_TIME_CNT;
    struct dg_perf_value* cnt = bpf_map_lookup_elem(&yadns_xdp_metrics, &cntid);
    if (cnt != NULL) {
        cnt->counter++;
    }

    u32 minid = JERICO_METRICS_TIME_MIN;
    struct dg_perf_value* min = bpf_map_lookup_elem(&yadns_xdp_metrics, &minid);
    if (min != NULL && cnt != NULL) {
        if (min->counter > t && cnt->counter > 1) {
            min->counter = t;
        }
        if (cnt->counter == 1) {
            min->counter = t;
        }
    }
}

SEC("xdp/xdp_dns")
int xdp_dns(struct xdp_md* ctx) {
    uint64_t start = 0;
    if (yadns_xdp_bpf_metrics_enabled) {
        start = bpf_ktime_get_ns();
    }

    // overriding runtime configured values (if any)
    bool yadns_xdp_rt_bpf_dryrun = dg_config_bool(&yadns_xdp_runtime_config,
                                                  JERICO_RUNTIME_CONFIG_DYRUN, yadns_xdp_bpf_dryrun);

    struct ethhdr* eth;
    struct cursor c;
    uint16_t eth_proto;
    struct iphdr* ipv4;
    struct ipv6hdr* ipv6;

    cursor_init(&c, ctx);
    c.proto_payload = 0;
    c.proto_enc = 0;

    int r = DEFAULT_ACTION;

#ifdef DEBUG
    int data_len = bpf_xdp_get_buff_len(ctx);
    bpf_printk("yadns_xdp: get_buff_len: %d", data_len);
#endif

    // matching at least one destination address
    bool dst_matched = false;

    // pass the packet if it is not an ethernet one, parsing
    // ethernet, vlan and ip headers, T.B.D. ipip
    if ((eth = parse_eth(&c, &eth_proto))) {
        if (eth_proto == bpf_htons(ETH_P_IP)) {
            if (!(ipv4 = parse_iphdr(&c))) {
                return DEFAULT_ACTION;
            }

            c.proto_payload = ETH_P_IP;
            dst_matched = yadns_xdp_dstaddr4(ipv4->daddr);

            // ip4ip6 case, I believe we do not have such case

            // ip4ip4 case, l3 makes such transport if ip4 VS and ip4 RS
            if (bpf_htons(ipv4->protocol == IPPROTO_IPIP)) {
                struct iphdr* ipv4;
                if (!(ipv4 = parse_iphdr(&c)) || bpf_htons(ipv4->protocol != IPPROTO_UDP)) {
                    return DEFAULT_ACTION;
                }

                c.proto_enc = ETH_P_IP;
                dst_matched = yadns_xdp_dstaddr4(ipv4->daddr);

                // stub plumber to turn ON/OFF ip6ip6
                //return DEFAULT_ACTION;
            }

            // ip4 normal packet without any encapsulation
            if (bpf_htons(ipv4->protocol != IPPROTO_UDP) && c.proto_enc == 0) {
                return DEFAULT_ACTION;
            }

        } else if (eth_proto == bpf_htons(ETH_P_IPV6)) {
            if (!(ipv6 = parse_ipv6hdr(&c))) {
                return DEFAULT_ACTION;
            }

            c.proto_payload = ETH_P_IPV6;
            dst_matched = yadns_xdp_dstaddr6(&ipv6->daddr);

            // ip6ip6 case, we need strip out tunnel ip6 header
            if (bpf_htons(ipv6->nexthdr == IPPROTO_IPV6)) {
                struct ipv6hdr* ipv6;
                if (!(ipv6 = parse_ipv6hdr(&c)) || bpf_htons(ipv6->nexthdr != IPPROTO_UDP)) {
                    return DEFAULT_ACTION;
                }

                c.proto_enc = ETH_P_IPV6;
                dst_matched = yadns_xdp_dstaddr6(&ipv6->daddr);

                // stub plumber to turn ON/OFF ip6ip6
                // return DEFAULT_ACTION;
            }

            // ip6ip4 case, please be careful we need at least
            // different ipip processing for this case
            if (bpf_htons(ipv6->nexthdr == IPPROTO_IPIP)) {
                struct iphdr* ipv4;
                if (!(ipv4 = parse_iphdr(&c)) || bpf_htons(ipv4->protocol != IPPROTO_UDP)) {
                    return DEFAULT_ACTION;
                }

                c.proto_payload = ETH_P_IP;
                c.proto_enc = ETH_P_IPV6;
                dst_matched = yadns_xdp_dstaddr4(ipv4->daddr);

                // stub plumber to turn ON/OFF ip6ip4
                //return DEFAULT_ACTION;
            }

            // ip6 normal packet without any encapsulation
            if (bpf_htons(ipv6->nexthdr != IPPROTO_UDP) && c.proto_enc == 0) {
                return DEFAULT_ACTION;
            }
        }
    }

    if (dst_matched && c.proto_payload > 0) {
        // processing dns packet later, in cursor
        // we have ip4 and ip6 proto class set
        r = yadns_xdp_dns_process(ctx, &c, yadns_xdp_rt_bpf_dryrun);
    }

    if (r == XDP_TX) {
        if (yadns_xdp_bpf_metrics_enabled) {
            u64 t = bpf_ktime_get_ns() - start;

            dg_histogram_log2_update(&yadns_xdp_perf, t);
            yadns_xdp_metrics_update(t);
        }

        if (yadns_xdp_bpf_xdpcap_enabled) {
            // calling xdpcap_hook program of xdpcap
            xdpcap_exit(ctx, &xdpcap_hook, r);
        }
    }

    return r;
}

char _license[] SEC("license") = "GPL";
