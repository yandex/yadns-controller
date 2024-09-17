package receiver

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/slayer1366/yadns-controller/pkg/plugins/offloader"
)

type TSnapshotZone struct {
	p *TReceiverPlugin

	// name of zone of snapshot
	zone string

	// soa record
	soa dns.RR

	// timestamp
	timestamp time.Time

	// "imported" rrset snapshot data
	rrsets map[string][]dns.RR

	// imports actions detected for
	// current snapshot via blob or via
	// AXFR/IXFR methods
	imports *TImportActions
}

// Temporary structure to define a current state
// of imports for zone (could be reused in recevier?)
type TImportActions struct {
	// could be AXFR or IXFR
	mode int

	// zone in some cases should be found
	zone string

	// actions for IXFR mode
	actions *TSnapshotActions
}

const (
	SourceHTTP = 101
	SourceFile = 102
	SourceAXFR = 103

	SourceUnknown = 0

	// default zone snapshot options
	DefaultZoneSnapshotIncremental = true
)

type TZoneSnapshotOptions struct {

	// if snapshot will be incremental (default)
	Incremental bool

	// possible source type of snapshot, possible
	// values: SourceHTTP, SourceFile, SourceAXFR
	Source int

	// primary server to fetch data
	Server string

	// optional key (if set to some value AXFR
	// transfer uses it), should be set in DIG
	// format
	Key string

	// setting if memory snapshots already has
	// a snapshot of zone requested
	SnapshotMode int
}

func NewXFR(data string) ([]dns.RR, error) {
	rows := strings.Split(data, "\n")

	var rrsets []dns.RR
	for _, r := range rows {
		if len(r) == 0 || strings.HasPrefix(r, ";") {
			continue
		}
		rr, err := dns.NewRR(strings.TrimSpace(r))
		if err != nil {
			return rrsets, err
		}

		if rr == nil {
			continue
		}
		rrsets = append(rrsets, rr)
	}

	return rrsets, nil
}

func NewSnapshotZone(p *TReceiverPlugin, data string, zone string) (*TSnapshotZone, error) {
	id := "(snapshot)"

	rr, err := NewXFR(data)
	if err != nil {
		return nil, err
	}

	var config TConfigImporter
	config.Zone = append(config.Zone, zone)
	config.Server = "localhost"

	importer, err := NewImporterWorker(p, &config)
	if err != nil {
		return nil, err
	}

	rrsets, soa := importer.FilterZone(rr, ImportFilterLoosed)

	var snapshot TSnapshotZone
	snapshot.p = p
	snapshot.soa = soa
	snapshot.rrsets = rrsets

	snapshot.zone = zone
	if len(zone) == 0 {
		// zone name autodetection, skipping last dot
		// (if any) from fqdn name of SOA record
		fqdn, err := snapshot.Fqdn()
		if err != nil {
			return &snapshot, err
		}
		snapshot.zone = RemoveDot(fqdn)
	}

	snapshot.timestamp = time.Now()

	p.G().L.Debugf("%s received from  zone:'%s' bytes:'%d' rr:'%d' -> rrsets:'%d'", id,
		zone, len(data), len(rr), len(rrsets))

	return &snapshot, err
}

func NewSnapshotZoneFromFile(p *TReceiverPlugin, filename string,
	zone string) (*TSnapshotZone, error) {
	id := "(snapshot) (zone)"

	p.G().L.Debugf("%s reading zone:'%s' snapshot:'%s'", id, zone, filename)

	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	return NewSnapshotZone(p, string(content), zone)
}

func NewSnapshotZoneFromBlob(p *TReceiverPlugin, path string,
	zone string) (*TSnapshotZone, error) {

	filename := fmt.Sprintf("%s/%s.%s", path, Md5(zone), DefaultSnapshotSuffix)

	return NewSnapshotZoneFromFile(p, filename, zone)
}

func GetSnapshotFilename(p *TReceiverPlugin, zone string) string {
	path := p.L().Options.Snapshots.Directory
	return fmt.Sprintf("%s/%s.%s", path, Md5(zone), DefaultSnapshotSuffix)
}

func GetSnapshotID(zone string) string {
	md5 := Md5(zone)
	return md5[0:8]
}

func NewSnapshotZoneFromSnapshot(p *TReceiverPlugin, zone string) (*TSnapshotZone, error) {

	filename := GetSnapshotFilename(p, zone)

	// checking if snapshot of zone could be read and used
	// e.g. if it has some appropriate age
	if !ValidateSnapshotZoneFile(p, filename, zone) {
		err := fmt.Errorf("file:'%s' snapshot zone:'%s' could not be used", filename, zone)
		return nil, err
	}

	return NewSnapshotZoneFromFile(p, filename, zone)
}

func ValidateSnapshotZoneFile(p *TReceiverPlugin, filename string, zone string) bool {
	id := "(validate)"

	// getting a list of file attributes, could be 0
	// if file does not exist
	age := GetFileAge(filename)
	if age > 0 {
		options := p.L().Options
		max := options.Snapshots.ReadValidInterval

		valid := age < float64(max)
		desc := "VALID"
		if !valid {
			desc = "TOO OLD"
		}
		p.G().L.Debugf("%s snapshot filename:'%s' for zone:'%s' detected age:'%2.2f' seconds, limit:'%d' %s",
			id, filename, zone, age, max, desc)

		return valid
	}

	// checking all requirements later
	return true
}

type TZoneConfig struct {
	Zone string `json:"zone"`
}

func NewSnapshotZoneFromEndpoint(p *TReceiverPlugin, ctx context.Context,
	endpoint []string, zone string) (*TSnapshotZone, error) {

	id := "(snapshot) (endpoint)"

	var config TZoneConfig
	config.Zone = zone

	content, err := json.MarshalIndent(config, "", "   ")
	if err != nil {
		return nil, err
	}

	var body []byte
	for _, e := range endpoint {
		t0 := time.Now()
		p.G().L.Debugf("%s requesting zone:'%s' snapshot over endpoint:'%s'", id, zone, e)

		bodyReader := bytes.NewReader(content)

		req, err := http.NewRequestWithContext(ctx, "POST", e, bodyReader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", p.G().Runtime.GetUseragent())

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}

		defer resp.Body.Close()

		if body, err = io.ReadAll(resp.Body); err != nil {
			return nil, err
		}

		p.G().L.Debugf("%s recevied size:'%d' finished in '%s'",
			id, len(body), time.Since(t0))
	}

	return NewSnapshotZone(p, string(body), zone)
}

func (t *TSnapshotZone) WriteSnapshotZone(dryrun bool) error {
	var err error

	id := fmt.Sprintf("(snapshot) (blob) %s", DryrunString(dryrun))

	path := t.p.L().Options.Snapshots.Directory

	// checking if path does not exist, create it
	if err = os.MkdirAll(path, 0755); err != nil {
		t.p.G().L.Errorf("%s error creating path:'%s', err:'%s'", id, path, err)
		return nil
	}

	filename := fmt.Sprintf("%s/%s.%s", path, Md5(t.zone), DefaultSnapshotSuffix)
	t.p.G().L.Debugf("%s writing zone:'%s' blob snapshot:'%s'", id, t.zone, filename)

	if dryrun {
		t.p.G().L.Debugf("%s skip processing as dry-run set", id)
		return nil
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n", t.soa.String())

	for _, vv := range t.rrsets {
		for _, v := range vv {
			fmt.Fprintf(&b, "%s\n", v.String())
		}
	}
	fmt.Fprintf(&b, "%s\n", t.soa.String())

	if err = os.WriteFile(filename, []byte(b.String()), 0644); err != nil {
		return err
	}

	return nil
}

func (t *TSnapshotZone) Dump(p *TReceiverPlugin, did string, max int) {
	id := fmt.Sprintf("(snapshot) (dump) %s", did)

	if t.soa != nil {
		// snapshot could be a list of zones in
		// AXFR mode sync map
		p.G().L.Infof("%s soa:'%s'", id, t.soa.String())
	}
	p.G().L.Infof("%s timestamp:'%s'", id, t.timestamp)

	count := 0
	for k, rrsets := range t.rrsets {
		for i, rr := range rrsets {
			p.G().L.Infof("%s k:'%s' [%d] [%d]/[%d] %s", id,
				k, i, count, len(rrsets), rr.String())
		}
		count++
		if count > max && max > 0 {
			break
		}
	}
}

func (t *TSnapshotZone) Equal(s *TSnapshotZone) bool {
	s1 := make(map[string]dns.RR)
	s2 := make(map[string]dns.RR)

	for _, vv := range t.rrsets {
		for _, v := range vv {
			s1[v.String()] = v
		}
	}

	for _, vv := range s.rrsets {
		for _, v := range vv {
			s2[v.String()] = v
		}
	}

	// checking in both directions
	for k := range s1 {
		if _, ok := s2[k]; !ok {
			return false
		}
	}

	for k := range s2 {
		if _, ok := s1[k]; !ok {
			return false
		}
	}

	return true
}

func (t *TSnapshotZone) Refresh() (uint32, error) {
	if t.soa == nil {
		return 0, nil
	}
	if t.soa.Header().Rrtype != dns.TypeSOA {
		err := fmt.Errorf("snapshot has no SOA record")
		return 0, err
	}
	rr := t.soa.(*dns.SOA)
	return rr.Refresh, nil
}

func (t *TSnapshotZone) Serial() (uint32, error) {
	if t.soa == nil {
		return 0, nil
	}
	if t.soa.Header().Rrtype != dns.TypeSOA {
		err := fmt.Errorf("snapshot has no SOA record")
		return 0, err
	}
	rr := t.soa.(*dns.SOA)
	return rr.Serial, nil
}

func (t *TSnapshotZone) SOA() (string, error) {
	if t.soa == nil {
		return "", nil
	}

	if t.soa.Header().Rrtype != dns.TypeSOA {
		err := fmt.Errorf("snapshot has no SOA record")
		return "", err
	}
	rr := t.soa.(*dns.SOA)
	str := fmt.Sprintf("%s %s %d %d %d %d %d", rr.Ns, rr.Mbox, rr.Serial,
		rr.Refresh, rr.Retry, rr.Expire, rr.Minttl)

	return str, nil
}

func (t *TSnapshotZone) Fqdn() (string, error) {
	if t.soa == nil {
		return "", nil
	}
	if t.soa.Header().Rrtype != dns.TypeSOA {
		err := fmt.Errorf("snapshot has no SOA record")
		return "", err
	}
	h := t.soa.Header()
	return h.Name, nil
}

const (
	// checking SOA serials for
	// first and last RR as AXFR
	// envelope
	SnapshotSOAFirst = 1
	SnapshotSOALast  = 2

	// constants to iterate over IXFR data
	SectionUnknown  = 0
	SectionAddition = 1
	SectionDeletion = 2
)

func SectionString(section int) string {
	names := map[int]string{
		SectionUnknown:  "UNKNOWN",
		SectionAddition: "CREATE",
		SectionDeletion: "REMOVE",
	}
	if _, ok := names[section]; !ok {
		return names[SectionUnknown]
	}
	return names[section]
}

// helper to detect if rr exists dns rrset, assuming that
// qname and qtype the same (as it derives from map
// in snapshot zone rrsets, returning an index
func (t *TSnapshotZone) Exists(rr dns.RR, rrset []dns.RR) int {

	// creating a map w.r.t IP address (ip4 or ip6)
	// and a TTL from header
	for i, r := range rrset {
		h1 := rr.Header()
		h2 := r.Header()

		if h1.Ttl != h2.Ttl {
			continue
		}
		switch h1.Rrtype {
		case dns.TypeA:
			ip1 := rr.(*dns.A).A
			ip2 := r.(*dns.A).A
			if ip1.Equal(ip2) {
				return i
			}
		case dns.TypeAAAA:
			ip1 := rr.(*dns.AAAA).AAAA
			ip2 := r.(*dns.AAAA).AAAA
			if ip1.Equal(ip2) {
				return i
			}
		}
	}
	return -1
}

func (t *TSnapshotZone) RemoveRRsets() {
	// See some notes about clearing a map in go
	// https://stackoverflow.com/questions/13812121/how-to-clear-a-map-in-go
	for k := range t.rrsets {
		delete(t.rrsets, k)
	}
}

type TSnapshotActions struct {

	// actions grouped by right order
	// from serial SOA upto current
	actions map[int]map[int]map[string][]dns.RR
}

func (t *TSnapshotActions) Add(action int, section int, key string, r dns.RR) {
	if _, ok := t.actions[action]; !ok {
		t.actions[action] = make(map[int]map[string][]dns.RR)
		types := []int{SectionUnknown, SectionAddition, SectionDeletion}
		for _, tt := range types {
			t.actions[action][tt] = make(map[string][]dns.RR)
		}
	}

	t.actions[action][section][key] =
		append(t.actions[action][section][key], r)
}

func (t *TSnapshotActions) Dump(p *TReceiverPlugin) {
	id := "(notifier) (snapshot) (actions) (dump)"

	var ixfr []int
	for k := range t.actions {
		ixfr = append(ixfr, k)
	}
	sort.Ints(ixfr)

	// we need here actions list and current already applied
	// IXFR to snapshot, as we have situations when some data
	// in additions should be removed (two addresses are
	// added)

	types := []int{SectionDeletion, SectionAddition}

	for _, i := range ixfr {

		actions := t.actions[i]
		for _, tt := range types {
			for k, rr := range actions[tt] {

				// as we could have in action a list of RR, applying
				// them w.r.t current state of rrset in snapshot
				for _, r := range rr {
					p.G().L.Debugf("%s ixfr:'%d' k:'%s' action:'%s' '%s'", id, i, k,
						SectionString(tt), r.String())
				}
			}
		}
	}
}

func (t *TSnapshotZone) ApplyIXFR(ixfr []dns.RR) (dns.RR, int, *TSnapshotActions, error) {

	id := "(snapshot) (ixfr)"

	var err error

	mode := TransferModeUnknown

	var soa dns.RR
	// We need apply IXFR received to snapshot
	// of zone, assuming that snapshot and ixfr
	// of the same zone source (SOA records should be
	// checked)

	if len(ixfr) <= 1 {
		// in this case no any valid updates are received
		// such case could be a result of serial number of
		// IXFR requested more then current master version
		return soa, mode, nil, nil
	}

	soas := make(map[int]uint32)

	var SA TSnapshotActions
	SA.actions = make(map[int]map[int]map[string][]dns.RR)

	// unknown section
	section := SectionUnknown

	// all actions are grouped by SOA IXFR, counting
	// action variable each time when deletion section
	// is seen
	action := -1

	// ixfr rrset should countain more than two SOA records, if
	// ixfr contains exactly two it is AXFR actually
	for i, r := range ixfr {

		t.p.G().L.Debugf("%s [%d]/[%d] RR '%s'", id, i, len(ixfr), r.String())

		h := r.Header()

		// checking last RR, they should be SOA with
		// the same serial number, if not we have incorrect
		// IXFR or AXFR
		if i == 0 || i == len(ixfr)-1 {

			if h.Rrtype != dns.TypeSOA {
				err = fmt.Errorf("SOA records misconfiguration")
				return soa, mode, &SA, err
			}
			if i == 0 {
				soas[SnapshotSOAFirst] = r.(*dns.SOA).Serial
				soa = r
				continue
			}
			soas[SnapshotSOALast] = r.(*dns.SOA).Serial
			continue
		}

		// all the rest seen SOA (if any) define IXFR updates
		// grouping in a list of pairs, first, - deletions, the
		// second one - additions. Update is defined as deletion
		// and than addition
		if h.Rrtype == dns.TypeSOA {

			switch section {
			case SectionUnknown:
				// first IXFR SOA is always deletion
				section = SectionDeletion
			case SectionDeletion:
				section = SectionAddition
			case SectionAddition:
				section = SectionDeletion
			}

			if section == SectionDeletion {
				action++
			}
			continue
		}

		if section == SectionUnknown {
			// waiting for addition or deletion section
			// also if there's no any one of expected
			// we have AXFR (see comments below)
			continue
		}

		// Here we have only RRSET records, and we need
		// filtering them to have A/AAAA only also checking
		// fqdn length

		// adding only ALLOWED types of RR
		if h.Rrtype == dns.TypeA || h.Rrtype == dns.TypeAAAA {
			if len(h.Name) >= offloader.DefaultQnameMaxLength {
				// skipping but we should ensure that
				// fqdn length is also could be skipped
				// w.r.t operations performed
				continue
			}
			key := fmt.Sprintf("%s-%s", h.Name, dns.Type(h.Rrtype).String())

			t.p.G().L.Debugf("%s %s [%d]/[%d] k:'%s' rr:'%s''\n", id, SectionString(section),
				i, len(ixfr), key, r.String())

			if _, ok := t.rrsets[key]; !ok {
				// we do not have corresponding key, deletation
				// is automatically skipped, for creation we need
				// check if record exists. Snapshot could contain
				// a multiple RRSET for one type
				switch section {
				case SectionAddition:
					SA.Add(action, SectionAddition, key, r)

					t.rrsets[key] = append(t.rrsets[key], r)
				}
				continue
			}

			rrset := t.rrsets[key]
			index := t.Exists(r, rrset)

			switch section {
			case SectionDeletion:
				if index >= 0 {
					t.rrsets[key] = SlicesDelete(t.rrsets[key], index, index+1)
					SA.Add(action, SectionDeletion, key, r)
					if len(t.rrsets[key]) == 0 {
						// also removing a map entry if no
						// any data found in slice
						delete(t.rrsets, key)
					}

				}
			case SectionAddition:
				//if index < 0 {
				t.rrsets[key] = append(t.rrsets[key], r)
				SA.Add(action, SectionAddition, key, r)
				//}
			}
		}
	}

	// we need to check first and last SOA record
	// if they have different serial, something went
	// wrong
	if soas[SnapshotSOALast] != soas[SnapshotSOAFirst] {
		err = fmt.Errorf("SOA records misconfiguration %d vs %d",
			soas[SnapshotSOAFirst], soas[SnapshotSOALast])
		return soa, mode, &SA, err
	}

	mode = TransferModeIXFR
	if section == SectionUnknown {
		mode = TransferModeAXFR
	}

	return soa, mode, &SA, nil
}

func (t *TSnapshotZone) Action(mode int, k string) (int, *dns.RR) {

	id := "(snapshot) (action) (map)"

	var rr *dns.RR

	count := 0
	_, exists := t.rrsets[k]
	if exists {
		count = len(t.rrsets[k])
	}

	// Making some rrset count magic inverting
	// the meaning of operations
	action := mode
	switch mode {
	case SectionAddition:
		// checking if number of rrset more than 1, we should
		// remove (instead of addition)
		if count > 1 {
			action = SectionDeletion
		}
	case SectionDeletion:
		if count == 1 {
			action = SectionAddition
			// T.B.D. in this case we need get a rr from
			// t.rrsets[k] (as its only one that exists)
			// and push it to the offloader.Map
			t := t.rrsets[k][0]
			rr = &t
		}
	}

	t.p.G().L.Debugf("%s mode:'%s' k:'%s' count:'%d' defines '%s'", id, SectionString(mode),
		k, count, SectionString(action))

	return action, rr
}

type TVerifyResult struct {
	// total count of rrsets
	Total int `json:"total"`

	// verified rrsets count
	Verified int `json:"verified"`

	// number of missed records
	Missed int `json:"missed"`

	// differ
	DifferOnTTL int `json:"differ-on-ttl"`
	DifferOnIP  int `json:"differ-on-ip"`

	// number of unexpected records
	Unexpected int `json:"unexpected"`
}

func (t *TVerifyResult) AsString() string {
	var out []string

	out = append(out, fmt.Sprintf("total:'%d'", t.Total))
	out = append(out, fmt.Sprintf("verified:'%d'", t.Verified))
	out = append(out, fmt.Sprintf("missed:'%d'", t.Missed))
	out = append(out, fmt.Sprintf("differonttl:'%d'", t.DifferOnTTL))
	out = append(out, fmt.Sprintf("differonip:'%d'", t.DifferOnIP))
	out = append(out, fmt.Sprintf("unexpected:'%d'", t.Unexpected))

	return strings.Join(out, ",")
}

func (t *TVerifyResult) AsJSON() []byte {
	body, _ := json.MarshalIndent(t, "", "  ")
	return body
}

func (t *TSnapshotZone) VerifyMap() (*TVerifyResult, *TChangedSetZone, error) {
	var err error
	id := "(snapshot) (verify) (map)"
	t.p.G().L.Debugf("%s request to verify map", id)

	rrmaps, err := t.LoadMaps()
	if err != nil {
		t.p.G().L.Errorf("%s error loading pinned maps, err:'%s'", id, err)
		return nil, nil, err
	}
	defer t.UnloadMaps(rrmaps)

	var result TVerifyResult
	result.Total = 0
	result.Verified = 0

	rrsrc := make(map[string]dns.RR)
	for i, rrset := range t.rrsets {
		result.Total += len(rrset)
		if len(rrset) > 1 {
			continue
		}
		for _, rr := range rrset {
			result.Verified++

			if result.Verified < DefaultDumpMaxRRsets {
				t.p.G().L.Debugf("%s [%d]/[%d] axfr k:'%s' VERIFY as %s'", id,
					result.Verified, len(t.rrsets), i, rr.String())
			}

			h := rr.Header()
			key := fmt.Sprintf("%s-%s", h.Name, dns.Type(h.Rrtype).String())
			rrsrc[key] = rr
		}
	}

	serial, _ := t.Serial()
	t.p.G().L.Debugf("%s src axfr zone:'%s' SOA serial:'%d' synced map entries:'%d' verified:'%d' as '%d'",
		id, t.zone, serial, result.Total, result.Verified, len(rrsrc))

	obj := NewObjects(t.p)

	rrs, err := obj.ListRR()
	if err != nil {
		t.p.G().L.Errorf("%s error listing bpf map rrsets, err:'%s'", id, err)
		return nil, nil, err
	}
	t.p.G().L.Debugf("%s dst bpf map count:'%d' src axfr on serial:'%d' '%d'",
		id, len(rrs), serial, len(rrsrc))

	rrdst := make(map[string]dns.RR)
	for _, rr := range rrs {
		h := rr.Header()
		key := fmt.Sprintf("%s-%s", h.Name, dns.Type(h.Rrtype).String())
		rrdst[key] = rr
	}

	var changed TChangedSetZone
	changed.age = time.Now().Unix()

	changed.rrchanges = make(map[int]map[string][]dns.RR)
	changes := []int{ChangeCreate, ChangeRemove}
	for _, change := range changes {
		changed.rrchanges[change] = make(map[string][]dns.RR)
	}
	changed.created = 0
	changed.removed = 0

	for k, rr := range rrsrc {
		if _, ok := rrdst[k]; !ok {
			result.Missed++
			if result.Missed < DefaultDumpMaxRRsets*10 {
				t.p.G().L.Debugf("%s missed on dst k:'%s' %s", id, k, rr.String())
			}

			changed.rrchanges[ChangeCreate][k] =
				append(changed.rrchanges[ChangeCreate][k], rr)
			changed.created++

			continue
		}

		replaced := false
		rrd := rrdst[k]
		if rr.Header().Ttl != rrd.Header().Ttl {
			result.DifferOnTTL++
			if result.DifferOnTTL < DefaultDumpMaxRRsets*10 {
				t.p.G().L.Debugf("%s differ on TTL dst k:'%s' src:'%s' dst:'%s'",
					id, k, rr.String(), rrd.String())
			}
			replaced = true
		}

		// T.B.D. optimization
		if rrd.String() != rr.String() {
			result.DifferOnIP++
			if result.DifferOnIP < DefaultDumpMaxRRsets*10 {
				t.p.G().L.Debugf("%s differ on IP dst k:'%s' src:'%s' dst:'%s'",
					id, k, rr.String(), rrd.String())
			}
			replaced = true
		}

		if replaced {
			changed.rrchanges[ChangeRemove][k] =
				append(changed.rrchanges[ChangeRemove][k], rrd)

			changed.rrchanges[ChangeCreate][k] =
				append(changed.rrchanges[ChangeCreate][k], rr)

			changed.removed++
			changed.created++
			continue
		}
	}

	for k, rr := range rrdst {
		if _, ok := rrsrc[k]; !ok {
			result.Unexpected++
			if result.Unexpected < DefaultDumpMaxRRsets*10 {
				t.p.G().L.Debugf("%s unexpected on dst k:'%s' %s", id, k, rr.String())
			}

			changed.rrchanges[ChangeRemove][k] =
				append(changed.rrchanges[ChangeRemove][k], rr)
			changed.created++

			continue
		}
	}

	changed.Dump(t.p, "(verifier) (changes)")

	return &result, &changed, err
}

func (t *TSnapshotZone) LoadMaps() (map[uint16]offloader.RRMap, error) {
	var err error
	id := "(snapshot) (load) (maps)"

	rrmaps := make(map[uint16]offloader.RRMap)
	types := []uint16{dns.TypeA, dns.TypeAAAA}

	for _, tt := range types {
		switch tt {
		case dns.TypeA:
			var rrmap offloader.RRMapA
			rrmap.PinPath = t.p.L().PinPath
			if err = rrmap.LoadPinnedMap(); err != nil {
				t.p.G().L.Errorf("%s error loading pinned map:'%s', err:'%s'", id, rrmap.MapName(), err)
				return rrmaps, err
			}
			rrmaps[tt] = &rrmap
		case dns.TypeAAAA:
			var rrmap offloader.RRMapAAAA
			rrmap.PinPath = t.p.L().PinPath
			if err = rrmap.LoadPinnedMap(); err != nil {
				t.p.G().L.Errorf("%s error loading pinned map:'%s', err:'%s'", id, rrmap.MapName(), err)
				return rrmaps, err
			}
			rrmaps[tt] = &rrmap
		}
	}

	return rrmaps, nil
}

func (t *TSnapshotZone) UnloadMaps(rrmaps map[uint16]offloader.RRMap) {
	id := "(snapshot) (unload)"
	for _, rrmap := range rrmaps {
		err := rrmap.Close()
		if err != nil {
			t.p.G().L.Errorf("%s error closing rrmaps, err:'%s'", id, err)
		}
	}
}

const (
	DryrunApply = "(APPLY)"
	DryrunSkip  = "(DRYRUN)"
)

func DryrunString(dryrun bool) string {
	names := map[bool]string{
		false: DryrunApply,
		true:  DryrunSkip,
	}
	return names[dryrun]
}

type TSyncMapResult struct {
	Created int `json:"created"`
	Removed int `json:"removed"`
}

func (t *TSyncMapResult) AsString() string {
	var out []string

	out = append(out, fmt.Sprintf("created:'%d'", t.Created))
	out = append(out, fmt.Sprintf("removed:'%d'", t.Removed))

	return strings.Join(out, ",")
}

func (t *TSnapshotZone) SyncMap(mode int, sa *TSnapshotActions,
	dryrun bool) (*TSyncMapResult, error) {

	var err error
	var result TSyncMapResult

	id := fmt.Sprintf("(snapshot) (sync) (map) %s", DryrunString(dryrun))

	rrmaps, err := t.LoadMaps()
	if err != nil {
		t.p.G().L.Errorf("%s error loading pinned maps, err:'%s'", id, err)
		return nil, err
	}
	defer t.UnloadMaps(rrmaps)

	obj := NewObjects(t.p)

	serial, _ := t.Serial()

	switch mode {
	case TransferModeAXFR:
		// sync map in AXFR mode assumes that we clean all
		// rr and push data (beware import mode only not
		// receiver, as receiver should make snapshots for
		// all configured zones at once, stacking data

		if !dryrun {
			if result.Removed, err = obj.CleanRR(); err != nil {
				t.p.G().L.Errorf("%s error cleaning map zone:'%s', err:'%s'",
					id, t.zone, err)
				return nil, err
			}
		}

		if dryrun {
			// showing some dryrun messages
			t.p.G().L.Debugf("%s skip clean RR in bpf map as dry-run set", id)
		}

		entries := 0
		created := 0
		for i, rrset := range t.rrsets {
			entries += len(rrset)

			// we have to skip all fqdn with IP addresses
			// more than N, at least N = 1
			if len(rrset) > 1 {
				continue
			}

			for _, rr := range rrset {
				h := rr.Header()
				created++

				dump := entries < DefaultDumpMaxRRsets*10
				if dump {
					t.p.G().L.Debugf("%s [%d]/[%d] axfr k:'%s' CREATE as %s'", id,
						created, len(t.rrsets), i,
						rr.String())
				}

				if !dryrun {
					if err = obj.UpdateDNSRR(ObjectCreate, rrmaps[h.Rrtype], rr, dump); err != nil {
						t.p.G().L.Errorf("%s error create rr:'%s', err:'%s'", id, rr.String(), err)
						return nil, err
					}
				}
			}
		}

		t.p.G().L.Debugf("%s axfr zone:'%s' SOA serial:'%d' synced map entries:'%d' created:'%d'",
			id, t.zone, serial, entries, created)

		result.Created = created

	case TransferModeIXFR:

		// actions are grouped by int number of IXFR group, so
		// we need to sort all keys first
		var ixfr []int
		for k := range sa.actions {
			ixfr = append(ixfr, k)
		}

		sort.Ints(ixfr)

		// we need here actions list and current already applied
		// IXFR to snapshot, as we have situations when some data
		// in additions should be removed (two addresses are
		// added)

		types := []int{SectionDeletion, SectionAddition}

		created := 0
		removed := 0

		for _, i := range ixfr {

			actions := sa.actions[i]

			for _, tt := range types {
				for k, rr := range actions[tt] {
					// as we could have in action a list of RR, applying
					// them w.r.t current state of rrset in snapshot
					for _, r := range rr {
						h := r.Header()

						// detecting if corresponding qname qtype exists
						// in map, checking ttl and IP address processing
						// all cases
						exists := obj.ExistsDNSRR(rrmaps[h.Rrtype], r)
						action, s := t.Action(tt, k)

						q := r

						if action == SectionAddition && s != nil {
							// implementing case if remove turns to
							// create and we need a current snapshot RR
							q = *s
						}

						dump := created+removed < 2*DefaultDumpMaxRRsets*100
						if dump {
							t.p.G().L.Debugf("%s ixfr:'%d' k:'%s' action:'%s' exists:'%s' '%s'", id, i, k,
								SectionString(action), ExitsAsString(exists),
								q.String())
						}

						var err error
						switch action {
						case SectionAddition:
							created++

							if !dryrun {
								switch exists {
								case NoExists:
									err = obj.UpdateDNSRR(ObjectCreate, rrmaps[h.Rrtype], q, dump)
								case ExistsEqual:
									// just skip, as we have requested item the same
									// as inserted
								case ExistsNotEqual:
									// remove current value and add requested
									err = obj.UpdateDNSRR(ObjectRemove, rrmaps[h.Rrtype], q, dump)
									if err == nil {
										err = obj.UpdateDNSRR(ObjectCreate, rrmaps[h.Rrtype], q, dump)
									}
								}
							}

						case SectionDeletion:
							removed++

							if !dryrun {
								switch exists {
								case NoExists:
									// no any key exists, just skipping
								case ExistsEqual, ExistsNotEqual:
									// trying to remove it as we could have situation
									// in IXFR then adding one more RR exceeds limit (now "1')
									// and we detect such situation as Deletion in the name
									// of limit (now "1")
									err = obj.UpdateDNSRR(ObjectRemove, rrmaps[h.Rrtype], q, dump)
								}
							}
						}

						if err != nil {
							t.p.G().L.Errorf("%s error create rr:'%s', err:'%s'", id, q.String(), err)
							continue
						}
					}
				}
			}

			t.p.G().L.Debugf("%s ixfr:'%d' zone:'%s' SOA serial:'%d' sync map created:'%d' removed:'%d'",
				id, i, t.zone, serial, created, removed)
		}

		result.Created = created
		result.Removed = removed
	}

	return &result, err
}
