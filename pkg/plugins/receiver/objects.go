package receiver

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/yandex/yadns-controller/pkg/plugins/offloader"
)

type TObjectFilter struct {
	// a filter for operations "clean", "list"
	Names []string

	// max number of rr sets to return
	Count int
}

// objects implements logics to read, update, remove
// a list of objects (mostly contained in bpf map)
type Objects struct {
	p *TReceiverPlugin

	// some options to override behaviuor, etc, dryrun
	Dryrun bool

	// filter to list data
	Filter TObjectFilter
}

func NewObjects(p *TReceiverPlugin) *Objects {
	var o Objects

	o.p = p

	// T.B.D. checking objects state, if we have corresponding
	// maps, objects cache etc...
	return &o
}

func (o *Objects) MatchFilter(e offloader.RREntry, filter TObjectFilter) bool {
	// Checking if e is matched to filter, we assume that
	// all IP, network based values correspond to a right side
	// of RR (ip4 or ip6) and regexp to the left

	for _, f := range filter.Names {
		// it could be network with ://, ip address
		// or regexp
		if strings.Contains(f, "::") {
			// T.B.D network convering and matching
			continue
		}

		re := regexp.MustCompile(f)

		name, err := UnpackName(e.Qname())
		// not matching if unpack with error
		if err != nil {
			return false
		}

		// assuming that all regexp corresponds to qname
		if !re.Match([]byte(name)) {
			return false
		}

		// T.B.D all other cases

	}
	return true
}

const (
	// objects to manage, first RR - is a RRset
	// actually we should have RRset includes only
	// one RR
	ObjectRR = iota

	// internal variants for operations
	ObjectCreate = iota
	ObjectRemove

	ObjectList
	ObjectClean
)

func ObjectModeAsString(mode int) string {
	names := map[int]string{
		ObjectCreate: "MAP CREATE",
		ObjectRemove: "MAP REMOVE",
	}

	if _, ok := names[mode]; ok {
		return names[mode]
	}

	return "MAP UNKNOWN"
}

const (
	EmptySuffix = ""
)

func (o *Objects) CreateRR(raw string) error {
	return o.UpdateRR(ObjectCreate, raw)
}

func (o *Objects) RemoveRR(raw string) error {
	return o.UpdateRR(ObjectRemove, raw)
}

func (o *Objects) UpdateRR(mode int, raw string) error {
	id := "(objects) (update) (rr)"
	o.p.G().L.Debugf("%s request create raw:'%s'", id, raw)

	// parsing dns record via newRR method
	rr, err := dns.NewRR(raw)
	if err != nil {
		o.p.G().L.Errorf("%s error parsing raw:'%s', err:'%s'", id, raw, err)
		return err
	}
	o.p.G().L.Debugf("%s parsing requested RR as '%s'", id, rr.String())

	qtype := rr.Header().Rrtype

	switch qtype {
	case dns.TypeA:
		var rrmap offloader.RRMapA
		rrmap.PinPath = o.p.L().PinPath
		if err = rrmap.LoadPinnedMap(); err != nil {
			o.p.G().L.Errorf("%s error loading pinned map:'%s', err:'%s'", id, rrmap.MapName(), err)
			return err
		}
		defer rrmap.Close()
		o.p.G().L.Debugf("%s loaded pinned map:'%s':OK", id, rrmap.MapName())

		err = o.UpdateDNSRR(mode, &rrmap, rr, true)
	case dns.TypeAAAA:
		var rrmap offloader.RRMapAAAA
		rrmap.PinPath = o.p.L().PinPath
		if err = rrmap.LoadPinnedMap(); err != nil {
			o.p.G().L.Errorf("%s error loading pinned map:'%s', err:'%s'", id, rrmap.MapName(), err)
			return err
		}
		defer rrmap.Close()
		o.p.G().L.Debugf("%s loaded pinned map:'%s':OK", id, rrmap.MapName())

		err = o.UpdateDNSRR(mode, &rrmap, rr, true)
	}

	return err
}

type ConvertRR struct {
	qname offloader.RRQname
	qtype uint16
	ttl   uint32
	ip    netip.Addr
}

func (c *ConvertRR) AsString() string {
	return fmt.Sprintf("name:'%s' qtype:'%d' ttl:'%d' ipaddr:'%s'",
		c.qname.AsString(), c.qtype, c.ttl, c.ip.String())
}

// HEADS UP: we need optimize ip conversions
func (o *Objects) ConvertDNSRR(rr dns.RR) (*ConvertRR, error) {
	var conv ConvertRR
	var err error

	conv.qtype = rr.Header().Rrtype
	conv.ttl = rr.Header().Ttl

	name := rr.Header().Name

	ipaddr := ""

	switch conv.qtype {
	case dns.TypeA:
		r := rr.(*dns.A)
		ipaddr = r.A.String()
	case dns.TypeAAAA:
		r := rr.(*dns.AAAA)
		ipaddr = r.AAAA.String()
	default:
		err = fmt.Errorf("unexpected dns type:'%s' expected one of ['A,AAAA']",
			dns.TypeToString[conv.qtype])
		return nil, err
	}

	conv.qname, err = PackName(name)
	if err != nil {
		return nil, err
	}

	if conv.ip, err = netip.ParseAddr(ipaddr); err != nil {
		return nil, err
	}

	return &conv, nil
}

func (o *Objects) UpdateDNSRR(mode int, rrmap offloader.RRMap, rr dns.RR, dump bool) error {
	id := "(objects) (update) (dns rr)"
	conv, err := o.ConvertDNSRR(rr)
	if err != nil {
		o.p.G().L.Errorf("%s error converting record, err:'%s'", id, err)
		return err
	}

	if dump {
		// heavy code here, need skip it later
		o.p.G().L.Debugf("%s %s %s", id, ObjectModeAsString(mode), conv.AsString())
	}

	return o.UpdateGenericRR(mode, rrmap, conv)
}

const (
	// codes indicating result of exists DNS RR
	// function, it checks if key in correspoding rrmap
	// exists. If exists it checks also ttl and IP
	// addresses requested rr and looked up
	NoExists       = 1001
	ExistsNotEqual = 1002
	ExistsEqual    = 1003

	ExistsUnknown = 0
)

func ExitsAsString(mode int) string {
	names := map[int]string{
		NoExists:       "NO EXISTS",
		ExistsNotEqual: "EXIST NOT EQUAL",
		ExistsEqual:    "EXISTS EQUAL",
		ExistsUnknown:  "EXISTS UNKNOWN",
	}

	if _, ok := names[mode]; ok {
		return names[mode]
	}

	return names[ExistsUnknown]
}

func (o *Objects) ExistsDNSRR(rrmap offloader.RRMap, rr dns.RR) int {
	id := "(objects) (exists)"

	conv, ttl, ip, err := o.LookupDNSRR(rrmap, rr)
	if err != nil {
		return NoExists
	}

	// ttl is not equal
	if ttl != rr.Header().Ttl {
		o.p.G().L.Debugf("%s TTL differs looked up '%s' vs requestes:'%s' ttl:'%d != %d'",
			id, conv.AsString(), rr.String(), ttl,
			rr.Header().Ttl)
		return ExistsNotEqual
	}

	// ip address requested and looked up are
	// not the same
	if ip.Compare(conv.ip) != 0 {
		o.p.G().L.Debugf("%s IP differs looked up '%s' vs requested:'%s' IP:'%s != %s'",
			id, conv.AsString(), rr.String(), ip.String(),
			conv.ip.String())
		return ExistsNotEqual
	}

	return ExistsEqual
}

func (o *Objects) LookupDNSRR(rrmap offloader.RRMap, rr dns.RR) (*ConvertRR, uint32, netip.Addr, error) {
	id := "(objects) (lookup) (dns rr)"
	conv, err := o.ConvertDNSRR(rr)
	if err != nil {
		o.p.G().L.Errorf("%s error converting record, err:'%s'", id, err)
		return nil, 0, netip.Addr{}, err
	}

	ttl, ip, err := o.LookupGenericRR(rrmap, conv.qname, conv.qtype)
	return conv, ttl, ip, err
}

func (o *Objects) LookupGenericRR(rrmap offloader.RRMap, qname offloader.RRQname,
	qtype uint16) (uint32, netip.Addr, error) {

	v, err := rrmap.Lookup(qname, qtype)
	if err != nil {
		return 0, netip.Addr{}, err
	}
	return v.QTTL(), v.IP(), err
}

func (o *Objects) UpdateGenericRR(mode int, rrmap offloader.RRMap, conv *ConvertRR) error {

	var err error
	id := "(objects) (update) (rr)"

	if o.Dryrun {
		err = fmt.Errorf("dryrun set")
		o.p.G().L.Errorf("%s error creating rr, err:'%s'", id, err)
		return err
	}

	switch mode {
	case ObjectCreate:
		if err = rrmap.Create(conv.qname, conv.qtype, conv.ttl, conv.ip); err != nil {
			o.p.G().L.Errorf("%s error creating rr on map:'%s' key:'%s' err:'%s'", id,
				rrmap.MapName(), conv.qname, err)
			return err
		}
	case ObjectRemove:
		// T.B.D. ttl and ip processing later
		if err = rrmap.Remove(conv.qname, conv.qtype); err != nil {
			o.p.G().L.Errorf("%s error removing rr, err:'%s'", id, err)
			return err
		}
	}
	return err
}

// we listing all supported types, A, AAAA for now
func (o *Objects) ListRR() ([]dns.RR, error) {

	id := "(objects) (list) (rr)"
	o.p.G().L.Debugf("%s request listing", id)
	var err error

	t0 := time.Now()

	var rrmapA offloader.RRMapA
	rrmapA.PinPath = o.p.L().PinPath

	var outA []dns.RR
	if outA, _, err = o.IterateGenericMapRR(ObjectList, &rrmapA); err != nil {
		return outA, err
	}

	var rrmapAAAA offloader.RRMapAAAA
	rrmapAAAA.PinPath = o.p.L().PinPath

	var outAAAA []dns.RR
	if outAAAA, _, err = o.IterateGenericMapRR(ObjectList, &rrmapAAAA); err != nil {
		return outAAAA, err
	}

	o.p.G().L.Debugf("%s finished in '%s'", id, time.Since(t0))

	outA = append(outA, outAAAA...)
	return outA, err
}

func (o *Objects) IterateGenericMapRR(mode int, rrmap offloader.RRMap) ([]dns.RR, int, error) {
	var err error
	var out []dns.RR

	id := "(objects) (iterate) (map) (rr)"

	if len(o.Filter.Names) > 0 {
		o.p.G().L.Debugf("%s filter:['%s']", id, strings.Join(o.Filter.Names, ","))
	}

	if err = rrmap.LoadPinnedMap(); err != nil {
		o.p.G().L.Errorf("%s error loading pinned map:'%s', err:'%s'", id, rrmap.MapName(), err)
		return out, 0, err
	}
	defer rrmap.Close()
	o.p.G().L.Debugf("%s loaded pinned map:'%s':OK", id, rrmap.MapName())

	var entries []offloader.RREntry
	if entries, err = rrmap.Entries(); err != nil {
		o.p.G().L.Errorf("%s error listing pinned map:'%s', err:'%s'", id, rrmap.MapName(), err)
		return out, 0, err
	}
	o.p.G().L.Debugf("%s loaded from bpf map:'%s' count:'%d", id, rrmap.MapName(), len(entries))

	max := 5
	for i, e := range entries {

		if o.Filter.Count > 0 && i >= o.Filter.Count {
			continue
		}

		if !o.MatchFilter(e, o.Filter) {
			continue
		}

		if i < max {
			o.p.G().L.Debugf("%s [%d]/[%d] %s", id, i, len(entries),
				e.AsRawString())
		}

		switch mode {
		case ObjectList:
			qname, err := UnpackName(e.Qname())
			if err != nil {
				o.p.G().L.Errorf("%s error unpacking data %s", id, e.AsRawString())
				return out, 0, err
			}

			raw := fmt.Sprintf("%s %d IN %s %s", Dot(qname), e.QTTL(),
				dns.TypeToString[e.Qtype()], e.Qdata())
			rr, err := dns.NewRR(raw)
			if err != nil {
				o.p.G().L.Errorf("%s error parsing raw:'%s', err:'%s'", id, raw, err)
				return out, 0, err
			}
			out = append(out, rr)
		case ObjectClean:
			if o.Dryrun {
				o.p.G().L.Errorf("%s error on clean as dry-run set", id)
				continue
			}
			if err = rrmap.Remove(e.Qname(), e.Qtype()); err != nil {
				o.p.G().L.Errorf("%s error removing rr, err:'%s'", id, err)
				return out, 0, err
			}
		}
	}

	o.p.G().L.Debugf("%s recevied entries:'%d'", id, len(entries))

	return out, len(entries), err
}

func (o *Objects) CleanRR() (int, error) {
	var err error
	c1 := 0
	c2 := 0

	id := "(objects) (clean) (rr)"
	o.p.G().L.Debugf("%s request cleaning", id)

	t0 := time.Now()

	var rrmapA offloader.RRMapA
	rrmapA.PinPath = o.p.L().PinPath
	if _, c1, err = o.IterateGenericMapRR(ObjectClean, &rrmapA); err != nil {
		return 0, err
	}
	var rrmapAAAA offloader.RRMapAAAA
	rrmapAAAA.PinPath = o.p.L().PinPath
	if _, c2, err = o.IterateGenericMapRR(ObjectClean, &rrmapAAAA); err != nil {
		return 0, err
	}

	o.p.G().L.Debugf("%s finished in '%s'", id, time.Since(t0))

	return c1 + c2, nil
}

// packing qname given as an fqdn name into dns based qname
// representation of type 0x6yandex0x3net
func PackName(qname string) (offloader.RRQname, error) {
	var pqname offloader.RRQname
	var err error

	// should we skip the last dot? key should in
	// dns packed form, so we do not need last dot
	// (if any)
	qname = strings.TrimRight(qname, ".")

	cnt := 0
	length := byte(len(qname))
	if length == 0 {
		return pqname, fmt.Errorf("illegal empty qname")
	}

	for i := byte(0); i < length; i++ {
		s := qname[i]
		if s == 46 || s == 0 || i == length-1 {
			pqname[i-byte(cnt)] = byte(cnt)

			if s == 0 {
				// c string notation ending with 0x0
				pqname[i-byte(cnt)] = byte(cnt)
				cnt = int(i + 1)
				break
			}

			if i == length-1 {
				// golang string notation
				pqname[i-byte(cnt)] = byte(cnt) + 1
				pqname[i+1] = s
				cnt = int(i + 1 + 1)
				break
			}

			cnt = -1
		}
		pqname[i+1] = s
		cnt++
	}

	max := pqname.MaxLength()
	if length+1 > max {
		return pqname, fmt.Errorf("qname too large:'%d' expected less than:'%d'", length+1, max)
	}

	pqname[cnt] = 0
	return pqname, err
}

// unpacking dns packed named into string notation
func UnpackName(pqname offloader.RRQname) (string, error) {

	length := byte(len(pqname))
	if length == 0 {
		return "", fmt.Errorf("illegal empty qname")
	}

	// setting max length of qname
	qname := make([]byte, length)

	cnt := pqname[0]
	tcnt := 1
	for i := byte(1); i < length; i++ {
		if pqname[i] == 0 {
			break
		}
		if cnt == 0 {
			cnt = pqname[i]
			qname[i-1] = '.'
			tcnt++
			continue
		}

		qname[i-1] = byte(pqname[i])
		tcnt++
		cnt--
	}

	// calculating length
	qname = qname[:tcnt-1]

	return string(qname), nil
}

func (o *Objects) ImportRR() error {

	id := "(objects) (import) (rr)"
	o.p.G().L.Debugf("%s request to import RR", id)

	t0 := time.Now()

	// T.B.D.

	o.p.G().L.Debugf("%s finished in '%s'", id, time.Since(t0))

	return nil
}
