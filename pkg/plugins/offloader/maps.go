package offloader

import (
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
)

/*
struct dns_query {
    uint16_t qtype;
    uint16_t qclass;
    char qname[MAX_DNS_NAME_LENGTH];
};

//Used as value of our A record hashmap
struct a_record {
    struct in_addr ip_addr;
    uint32_t ttl;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct dns_query);
    __type(value, struct a_record);
    __uint(max_entries, 32468);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} yadns_xdp_rr_a SEC(".maps");

*/

const (
	// we have default class IN with uint16 "1"
	DefaultClassIN = 1

	// a length of key for dns name used to
	// validate fqdn in import code
	DefaultQnameMaxLength = 48
)

// a length of array should be in sync with map in BPF
// program. I order to limit program variability is could
// be 256, 128, 96. 64, 48, 32
type RRQname [48]byte

func (t *RRQname) AsByteString() string {
	var b strings.Builder
	for _, s := range t {
		if s == 0 {
			break
		}
		fmt.Fprintf(&b, "0x%0x ", s)
	}
	return b.String()
}

func (t *RRQname) AsString() string {
	var b strings.Builder
	for _, s := range t {
		if s == 0 {
			break
		}
		if s > 32 {
			fmt.Fprintf(&b, "%c", s)
			continue
		}
		fmt.Fprintf(&b, "?")

	}
	return b.String()
}

func (t *RRQname) MaxLength() byte {
	return byte(DefaultQnameMaxLength - 1)
}

type RRKey struct {
	// question type and class
	Qtype  uint16 `json:"qtype"`
	Qclass uint16 `json:"qclass"`

	// a qname to match, see qname definition
	// #define MAX_DNS_NAME_LENGTH 256
	Qname RRQname `json:"qname"`
}

func (t *RRKey) AsRawString() string {
	var b strings.Builder
	fmt.Fprintf(&b, "qtype:'0x%0x' ", t.Qtype)
	fmt.Fprintf(&b, "qclass:'0x%0x' ", t.Qclass)
	fmt.Fprintf(&b, "qname:'%s'", t.Qname.AsString())
	return b.String()
}

type RRValue interface {
	AsRawString() string
}

// We have here ipv4 32bit value
type RRValueA struct {
	// unsigned long s_addr, use As4() for
	// ip4 address to fill
	Addr [4]byte `json:"addr"`

	// TTL for answer
	TTL uint32 `json:"ttl"`
}

func (t *RRValueA) AsRawString() string {
	var b strings.Builder
	fmt.Fprintf(&b, "addr:'0x%0x' ", t.Addr)
	fmt.Fprintf(&b, "ip4:'%s' ", netip.AddrFrom4(t.Addr).String())
	fmt.Fprintf(&b, "ttl:'0x%0x'", t.TTL)
	return b.String()
}

type RRValueAAAA struct {
	// use As16() for conversion
	Addr [16]byte `json:"addr"`

	// TTL for answer
	TTL uint32 `json:"ttl"`
}

func (t *RRValueAAAA) AsRawString() string {
	var b strings.Builder

	for i := 0; i < 4; i++ {
		fmt.Fprintf(&b, "'0x%0x':", t.Addr[i*4:(i+1)*4])
	}

	fmt.Fprintf(&b, "ip6:'%s' ", netip.AddrFrom16(t.Addr).String())
	fmt.Fprintf(&b, "ttl:'0x%0x'", t.TTL)
	return b.String()
}

type RREntry interface {
	// functions hidden
	AsRawString() string

	QnameAsBytes() []byte

	Qname() RRQname
	Qtype() uint16

	Qdata() string

	QTTL() uint32

	IP() netip.Addr
}

type RREntryA struct {
	RRKey
	RRValueA
}

func (m RREntryA) AsRawString() string {
	return fmt.Sprintf("key:'%s' bytes:'%s' value:'%s'",
		m.RRKey.AsRawString(), m.RRKey.Qname.AsByteString(),
		m.RRValueA.AsRawString())
}

func (m RREntryA) QnameAsBytes() []byte {
	return m.RRKey.Qname[:]
}

func (m RREntryA) Qname() RRQname {
	return m.RRKey.Qname
}

func (m RREntryA) Qtype() uint16 {
	return m.RRKey.Qtype
}

func (m RREntryA) Qdata() string {
	return netip.AddrFrom4(m.Addr).String()
}

func (m RREntryA) QTTL() uint32 {
	return m.TTL
}

func (m RREntryA) IP() netip.Addr {
	return netip.AddrFrom4(m.RRValueA.Addr)
}

type RRMap interface {
	MapName() string
	LoadPinnedMap() error
	Close() error

	Remove(qname RRQname, qtype uint16) error
	Create(qname RRQname, qtype uint16, ttl uint32, ip netip.Addr) error
	Update(qname RRQname, qtype uint16, ttl uint32, ip netip.Addr) error

	Lookup(qname RRQname, qtype uint16) (RREntry, error)

	Entries() ([]RREntry, error)
}

type RRMapA struct {
	Mp *ebpf.Map `ebpf:"yadns_xdp_rr_a"`

	PinPath string
}

func (m *RRMapA) MapName() string {
	return "yadns_xdp_rr_a"
}

func (m *RRMapA) LoadPinnedMap() error {
	var err error
	root := DefaultOffloaderPinPath
	if len(m.PinPath) > 0 {
		root = m.PinPath
	}
	path := filepath.Join(root, m.MapName())
	m.Mp, err = ebpf.LoadPinnedMap(path, nil)
	return err
}

func (m *RRMapA) Close() error {
	return m.Mp.Close()
}

func (m *RRMapA) Remove(qname RRQname, qtype uint16) error {
	key := RRKey{Qtype: qtype, Qclass: DefaultClassIN, Qname: qname}
	return m.Mp.Delete(key)
}

func (m *RRMapA) Create(qname RRQname, qtype uint16, ttl uint32, ip netip.Addr) error {
	return m.update(qname, qtype, ttl, ip, ebpf.UpdateNoExist)
}

func (m *RRMapA) Update(qname RRQname, qtype uint16, ttl uint32, ip netip.Addr) error {
	return m.update(qname, qtype, ttl, ip, ebpf.UpdateAny)
}

func (m *RRMapA) Lookup(qname RRQname, qtype uint16) (RREntry, error) {
	var v RRValueA
	key := RRKey{Qtype: qtype, Qclass: DefaultClassIN, Qname: qname}
	err := m.Mp.Lookup(key, &v)
	return RREntryA{RRKey: key, RRValueA: v}, err
}

func (m *RRMapA) Entries() ([]RREntry, error) {
	out := make([]RREntry, 0)
	var (
		entries = m.Mp.Iterate()
		key     RRKey
		value   RRValueA
	)
	for entries.Next(&key, &value) {
		out = append(out, RREntryA{
			RRKey{
				Qtype:  key.Qtype,
				Qclass: key.Qclass,
				Qname:  key.Qname,
			},
			RRValueA{
				Addr: value.Addr,
				TTL:  value.TTL,
			},
		})
	}
	if err := entries.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func (m *RRMapA) update(qname RRQname, qtype uint16, ttl uint32,
	ip netip.Addr, flags ebpf.MapUpdateFlags) error {

	key := RRKey{Qtype: qtype, Qclass: DefaultClassIN, Qname: qname}
	value := RRValueA{Addr: ip.As4(), TTL: ttl}

	return m.Mp.Update(key, value, flags)
}

type RREntryAAAA struct {
	RRKey
	RRValueAAAA
}

func (m RREntryAAAA) AsRawString() string {
	return fmt.Sprintf("key:'%s' bytes:'%s' value:'%s'",
		m.RRKey.AsRawString(), m.RRKey.Qname.AsByteString(),
		m.RRValueAAAA.AsRawString())
}

func (m RREntryAAAA) QnameAsBytes() []byte {
	return m.RRKey.Qname[:]
}

func (m RREntryAAAA) Qname() RRQname {
	return m.RRKey.Qname
}

func (m RREntryAAAA) Qtype() uint16 {
	return m.RRKey.Qtype
}

func (m RREntryAAAA) Qdata() string {
	return netip.AddrFrom16(m.Addr).String()
}

func (m RREntryAAAA) QTTL() uint32 {
	return m.TTL
}

func (m RREntryAAAA) IP() netip.Addr {
	return netip.AddrFrom16(m.RRValueAAAA.Addr)
}

type RRMapAAAA struct {
	Mp *ebpf.Map `ebpf:"yadns_xdp_rr_aaaa"`

	PinPath string
}

func (m *RRMapAAAA) MapName() string {
	return "yadns_xdp_rr_aaaa"
}

func (m *RRMapAAAA) LoadPinnedMap() error {
	var err error
	root := DefaultOffloaderPinPath
	if len(m.PinPath) > 0 {
		root = m.PinPath
	}
	path := filepath.Join(root, m.MapName())
	m.Mp, err = ebpf.LoadPinnedMap(path, nil)
	return err
}

func (m *RRMapAAAA) Close() error {
	return m.Mp.Close()
}

func (m *RRMapAAAA) Remove(qname RRQname, qtype uint16) error {
	key := RRKey{Qtype: qtype, Qclass: DefaultClassIN, Qname: qname}
	return m.Mp.Delete(key)
}

func (m *RRMapAAAA) Create(qname RRQname, qtype uint16, ttl uint32, ip netip.Addr) error {
	return m.update(qname, qtype, ttl, ip, ebpf.UpdateNoExist)
}

func (m *RRMapAAAA) Update(qname RRQname, qtype uint16, ttl uint32, ip netip.Addr) error {
	return m.update(qname, qtype, ttl, ip, ebpf.UpdateAny)
}

func (m *RRMapAAAA) Lookup(qname RRQname, qtype uint16) (RREntry, error) {
	var v RRValueAAAA
	key := RRKey{Qtype: qtype, Qclass: DefaultClassIN, Qname: qname}
	err := m.Mp.Lookup(key, &v)
	return RREntryAAAA{RRKey: key, RRValueAAAA: v}, err
}

func (m *RRMapAAAA) Entries() ([]RREntry, error) {
	out := make([]RREntry, 0)
	var (
		entries = m.Mp.Iterate()
		key     RRKey
		value   RRValueAAAA
	)
	for entries.Next(&key, &value) {
		out = append(out, RREntryAAAA{
			RRKey{
				Qtype:  key.Qtype,
				Qclass: key.Qclass,
				Qname:  key.Qname,
			},
			RRValueAAAA{
				Addr: value.Addr,
				TTL:  value.TTL,
			},
		})
	}
	if err := entries.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func (m *RRMapAAAA) update(qname RRQname, qtype uint16, ttl uint32,
	ip netip.Addr, flags ebpf.MapUpdateFlags) error {

	key := RRKey{Qtype: qtype, Qclass: DefaultClassIN, Qname: qname}
	value := RRValueAAAA{Addr: ip.As16(), TTL: ttl}

	return m.Mp.Update(key, value, flags)
}

type IPNet struct {
	IP   netip.Addr
	Mask uint32
	Bits int
}

func (m *IPNet) AsString() string {
	var out []string

	out = append(out, fmt.Sprintf("IP:'%s'", m.IP.String()))
	out = append(out, fmt.Sprintf("mask:'%d'", m.Mask))
	out = append(out, fmt.Sprintf("bits:'%d'", m.Bits))

	return strings.Join(out, ",")
}

func (m *IPNet) UnmarshalText(text []byte) error {
	_, cidr, err := net.ParseCIDR(string(text))
	if err != nil {
		return err
	}

	ones, bits := cidr.Mask.Size()
	if bits != 128 && bits != 32 {
		return fmt.Errorf("only IPv6 or IPv4 addresses supported")
	}

	m.IP, _ = netip.AddrFromSlice(cidr.IP)
	m.Mask = uint32(ones)
	m.Bits = bits

	return nil
}

func (m *IPNet) AsDNSDaddr6() TDnsDaddr6 {
	return TDnsDaddr6{
		PrefixLen: m.Mask,
		Addr:      m.IP.As16(),
	}
}

func (m *IPNet) AsDNSDaddr4() TDnsDaddr4 {
	return TDnsDaddr4{
		PrefixLen: m.Mask,
		Addr:      m.IP.As4(),
	}
}

func NewIPNetFromIP4(addr TDnsDaddr4) IPNet {
	var net IPNet

	net.IP = netip.AddrFrom4(addr.Addr)
	net.Mask = addr.PrefixLen
	net.Bits = 32

	return net
}

func NewIPNetFromIP6(addr TDnsDaddr6) IPNet {
	var net IPNet

	net.IP = netip.AddrFrom16(addr.Addr)
	net.Mask = addr.PrefixLen
	net.Bits = 128

	return net
}

type PassMap interface {
	MapName() string
	LoadPinnedMap() error
	Entries() (map[string]TAddr, error)
	Close() error

	Update(prefix TAddr) error
	// Create(prefix IPNet) error
	Remove(prefix TAddr) error
}

type TAddr struct {
	network IPNet
	value   uint8
}

func NewAddr(network IPNet, value uint8) TAddr {
	return TAddr{network: network, value: value}
}

func (t *TAddr) Network() *IPNet {
	return &t.network
}

func (t *TAddr) Value() uint8 {
	return t.value
}

/*
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct dns_daddr6);
    __type(value, u8);
    __uint(max_entries, 128);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} daddr6_pass SEC(".maps");
*/

type PassMap6 struct {
	Mp *ebpf.Map `ebpf:"daddr6_pass"`

	PinPath string
}

type TDnsDaddr6 struct {
	// prefix of the network
	PrefixLen uint32

	// in V6 version we have 16 bytes slice
	Addr [16]byte
}

func (m *PassMap6) LoadPinnedMap() error {
	var err error
	root := DefaultOffloaderPinPath
	if len(m.PinPath) > 0 {
		root = m.PinPath
	}
	path := filepath.Join(root, m.MapName())
	m.Mp, err = ebpf.LoadPinnedMap(path, nil)
	return err
}

func (m *PassMap6) MapName() string {
	return "daddr6_pass"
}

func (m *PassMap6) Close() error {
	return m.Mp.Close()
}

func (m *PassMap6) Update(prefix TAddr) error {
	return m.Mp.Update(prefix.network.AsDNSDaddr6(), prefix.value, ebpf.UpdateAny)
}

func (m *PassMap6) Remove(prefix TAddr) error {
	return m.Mp.Delete(prefix.network.AsDNSDaddr6())
}

func (m *PassMap6) Entries() (map[string]TAddr, error) {
	out := make(map[string]TAddr)
	var (
		entries = m.Mp.Iterate()
		key     TDnsDaddr6
		value   uint8
	)
	for entries.Next(&key, &value) {
		net := NewIPNetFromIP6(key)
		out[net.IP.String()] = TAddr{network: net, value: value}
	}
	if err := entries.Err(); err != nil {
		return out, err
	}
	return out, nil
}

/*
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct dns_daddr4);
    __type(value, u8);
    __uint(max_entries, 128);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} daddr4_pass SEC(".maps");
*/

type PassMap4 struct {
	Mp *ebpf.Map `ebpf:"daddr4_pass"`

	PinPath string
}

type TDnsDaddr4 struct {
	// prefix of the network
	PrefixLen uint32

	// in V6 version we have 16 bytes slice
	Addr [4]byte
}

func (m *PassMap4) LoadPinnedMap() error {
	var err error
	root := DefaultOffloaderPinPath
	if len(m.PinPath) > 0 {
		root = m.PinPath
	}
	path := filepath.Join(root, m.MapName())
	m.Mp, err = ebpf.LoadPinnedMap(path, nil)
	return err
}

func (m *PassMap4) MapName() string {
	return "daddr4_pass"
}

func (m *PassMap4) Close() error {
	return m.Mp.Close()
}

func (m *PassMap4) Update(prefix TAddr) error {
	return m.Mp.Update(prefix.network.AsDNSDaddr4(), prefix.value, ebpf.UpdateAny)
}

func (m *PassMap4) Remove(prefix TAddr) error {
	return m.Mp.Delete(prefix.network.AsDNSDaddr4())
}

func (m *PassMap4) Entries() (map[string]TAddr, error) {
	out := make(map[string]TAddr)
	var (
		entries = m.Mp.Iterate()
		key     TDnsDaddr4
		value   uint8
	)
	for entries.Next(&key, &value) {
		net := NewIPNetFromIP4(key)
		out[net.IP.String()] = TAddr{network: net, value: value}
	}
	if err := entries.Err(); err != nil {
		return out, err
	}
	return out, nil
}

/*
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct dg_perf_value);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} yadns_xdp_perf SEC(".maps");
*/

type PerfHistorgram struct {
	Mp *ebpf.Map `ebpf:"yadns_xdp_perf"`

	PinPath string
}

type TPerfValue struct {
	// a counter number in a cell of
	// historgram (counts of time)
	Counter uint64
}

func (m *PerfHistorgram) LoadPinnedMap() error {
	var err error
	root := DefaultOffloaderPinPath
	if len(m.PinPath) > 0 {
		root = m.PinPath
	}
	path := filepath.Join(root, m.MapName())
	m.Mp, err = ebpf.LoadPinnedMap(path, nil)
	return err
}

func (m *PerfHistorgram) MapName() string {
	return "yadns_xdp_perf"
}

func (m *PerfHistorgram) Close() error {
	return m.Mp.Close()
}

func (m *PerfHistorgram) Entries() ([64]uint64, error) {
	out := [64]uint64{}
	var (
		entries = m.Mp.Iterate()
		key     uint32
		value   uint64
	)
	for entries.Next(&key, &value) {
		out[key] = value
	}
	if err := entries.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func (m *PerfHistorgram) Keys() ([64]uint32, error) {
	out := [64]uint32{}
	counter := uint32(0)
	var (
		entries = m.Mp.Iterate()
		key     uint32
		value   uint64
	)
	for entries.Next(&key, &value) {
		out[counter] = key
		counter++
	}
	if err := entries.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func (m *PerfHistorgram) Update(key uint32, value uint64) error {
	return m.Mp.Update(key, value, ebpf.UpdateAny)
}

func (m *PerfHistorgram) Zero(key uint32) error {
	return m.Update(key, uint64(0))
}

func (m *PerfHistorgram) ZeroAll() error {
	keys, err := m.Keys()
	if err != nil {
		return err
	}
	for _, k := range keys {
		err := m.Update(k, uint64(0))
		if err != nil {
			return err
		}
	}
	return nil
}

/*
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct dg_perf_value);
    __uint(max_entries, 64);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} yadns_xdp_metrics SEC(".maps");

// counters for packets RX, TX and PASS
#define JERICO_METRICS_PACKETS_RX 0
#define JERICO_METRICS_PACKETS_TX 1
#define JERICO_METRICS_PACKETS_PASS 2

// please note we have the limit of MAX
#define JERICO_METRICS_MAX 63
*/

const (
	JericoMetricsPacketRX    = 0
	JericoMetricsPacketTX    = 1
	JericoMetricsPacketPass  = 2
	JericoMetricsPacketError = 3

	JericoMetricsMax = 63
)

type BpfMetrics interface {
	MapName() string
	LoadPinnedMap() error
	Close() error

	Entries() ([64]uint64, error)
	ZeroAll() error
}

type PerfMetrics struct {
	Mp *ebpf.Map `ebpf:"yadns_xdp_metrics"`

	PinPath string
}

func (m *PerfMetrics) LoadPinnedMap() error {
	var err error
	root := DefaultOffloaderPinPath
	if len(m.PinPath) > 0 {
		root = m.PinPath
	}
	path := filepath.Join(root, m.MapName())
	m.Mp, err = ebpf.LoadPinnedMap(path, nil)
	return err
}

func (m *PerfMetrics) MapName() string {
	return "yadns_xdp_metrics"
}

func (m *PerfMetrics) Close() error {
	return m.Mp.Close()
}

func (m *PerfMetrics) Entries() ([64]uint64, error) {
	out := [64]uint64{}
	var (
		entries = m.Mp.Iterate()
		key     uint32
		value   uint64
	)
	for entries.Next(&key, &value) {
		out[key] = value
	}
	if err := entries.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func (m *PerfMetrics) Keys() ([64]uint32, error) {
	out := [64]uint32{}
	counter := uint32(0)
	var (
		entries = m.Mp.Iterate()
		key     uint32
		value   uint64
	)
	for entries.Next(&key, &value) {
		out[counter] = key
		counter++
	}
	if err := entries.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func (m *PerfMetrics) Update(key uint32, value uint64) error {
	return m.Mp.Update(key, value, ebpf.UpdateAny)
}

func (m *PerfMetrics) Zero(key uint32) error {
	return m.Update(key, uint64(0))
}

func (m *PerfMetrics) ZeroAll() error {
	keys, err := m.Keys()
	if err != nil {
		return err
	}
	for _, k := range keys {
		err := m.Update(k, uint64(0))
		if err != nil {
			return err
		}
	}
	return nil
}

/*
#define JERICO_RUNTIME_CONFIG_DYRUN 0

// map to configure bpf in runtime
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, u32);
    __uint(max_entries, 16);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} yadns_xdp_runtime_config SEC(".maps");

*/

const (
	JericoRuntimeConfigDryrun = 0
)

type JericoRuntimeConfig struct {
	Mp *ebpf.Map `ebpf:"yadns_xdp_runtime_config"`

	PinPath string
}

func (m *JericoRuntimeConfig) LoadPinnedMap() error {
	var err error
	root := DefaultOffloaderPinPath
	if len(m.PinPath) > 0 {
		root = m.PinPath
	}
	path := filepath.Join(root, m.MapName())
	m.Mp, err = ebpf.LoadPinnedMap(path, nil)
	return err
}

func (m *JericoRuntimeConfig) MapName() string {
	return "yadns_xdp_runtime_config"
}

func (m *JericoRuntimeConfig) Close() error {
	return m.Mp.Close()
}

func (m *JericoRuntimeConfig) Update(key uint32, value uint32) error {
	return m.Mp.Update(key, value, ebpf.UpdateAny)
}

func (m *JericoRuntimeConfig) Entries() ([]uint32, error) {
	out := []uint32{}
	var (
		entries = m.Mp.Iterate()
		key     uint32
		value   uint32
	)
	for entries.Next(&key, &value) {
		out = append(out, value)
	}
	if err := entries.Err(); err != nil {
		return out, err
	}
	return out, nil
}

func (t *TXdpService) GetPassMaps(tag string, names []string) (map[string]map[string]TAddr, map[string]PassMap, error) {
	id := "(xdp) (pass)"
	var err error

	options := t.p.L().Options

	daddrmaps := make(map[string]map[string]TAddr)
	daddrs := make(map[string]PassMap)

	for _, name := range names {

		switch name {
		case "daddr6_pass":
			var passmap PassMap6
			passmap.PinPath = options.PinPath
			if err = passmap.LoadPinnedMap(); err != nil {
				t.p.G().L.Errorf("%s error load pinned map by name:'%s', err:'%s'", id, name, err)
				return nil, nil, err
			}
			daddrs[name] = &passmap

		case "daddr4_pass":
			var passmap PassMap4
			passmap.PinPath = options.PinPath
			if err = passmap.LoadPinnedMap(); err != nil {
				t.p.G().L.Errorf("%s error load pinned map by name:'%s', err:'%s'", id, name, err)
				return nil, nil, err
			}
			daddrs[name] = &passmap
		}

		dst, err := daddrs[name].Entries()
		if err != nil {
			t.p.G().L.Errorf("%s error getting entries from name:'%s', err:'%s'", id, name, err)
			return nil, nil, err
		}
		t.p.G().L.Debugf("%s received entries:'%d' from map:'%s'", id, len(dst), name)

		count := 0
		for _, net := range dst {
			t.p.G().L.Debugf("%s map:'%s' (dump) [%d]/[%d] %s", id, name,
				count, len(dst), net.network.AsString())
			count++
		}

		if _, ok := daddrmaps[name]; !ok {
			daddrmaps[name] = make(map[string]TAddr)
		}

		daddrmaps[name] = dst
	}

	return daddrmaps, daddrs, nil
}
