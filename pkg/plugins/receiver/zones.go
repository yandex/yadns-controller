package receiver

import (
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

type ZonesState struct {
	p *TReceiverPlugin

	// state of zone updated
	zones map[string]TZoneState

	// lock for update zone state
	locks map[string]*sync.Mutex
}

const (
	ZoneStateUnknown = 0

	// zone state clean
	ZoneStateClean = 110

	// zone state dirty
	ZoneStateDirty = 111
)

func ZoneStateAsString(state int) string {
	values := map[int]string{
		ZoneStateUnknown: "unknown",
		ZoneStateClean:   "clean",
		ZoneStateDirty:   "dirty",
	}
	if _, ok := values[state]; !ok {
		return values[state]
	}
	return values[state]
}

type TZoneState struct {
	// a name of zone
	Zone string `json:"zone"`

	// static configuration (with primary server and
	// some options, e.g. overriding SOA zone min)
	Config *TConfigZone `json:"config"`

	// a zone state should be
	Snapshots map[int]TSnapshotZone `json:"snapshots"`

	// number of snapshots
	SnapshotCount int `json:"snapshot-count"`

	// current snapshot ID, should be [0...SnapshotCount-1]
	SnapshotID int `json:"snapshot"`

	// dirty flag calculated after current snapshot
	// is received, this could be done either by
	State int `json:"state"`
}

const (
	// operations for changed set as CREATE
	// and REMOVE (update should be done as
	// REMOVE + CREATE of the same key)
	ChangeCreate = 1001
	ChangeRemove = 1002
)

func ChangeAsString(change int) string {
	names := map[int]string{
		ChangeCreate: "CREATE",
		ChangeRemove: "REMOVE",
	}
	if _, ok := names[change]; !ok {
		return "UNKNOWN"
	}
	return names[change]
}

type TChangedSetZone struct {
	age int64

	rrchanges map[int]map[string][]dns.RR

	created int
	removed int
}

func (t *TChangedSetZone) AsActions() *TSnapshotActions {

	var actions TSnapshotActions
	actions.actions = make(map[int]map[int]map[string][]dns.RR)

	changes := []int{ChangeRemove, ChangeCreate}
	for _, change := range changes {
		for k, rrsets := range t.rrchanges[change] {
			for _, rr := range rrsets {

				section := SectionDeletion
				if change == ChangeCreate {
					section = SectionAddition
				}

				actions.Add(0, section, k, rr)
			}
		}
	}

	return &actions
}

func (t *TChangedSetZone) Dump(p *TReceiverPlugin, did string) {
	id := fmt.Sprintf("(dump) %s", did)

	p.G().L.Debugf("%s age:'%d'", id, t.age)

	changes := []int{ChangeRemove, ChangeCreate}
	for _, change := range changes {
		for k, rrsets := range t.rrchanges[change] {
			for i, rr := range rrsets {
				p.G().L.Debugf("%s %s k:'%s' [%d]/[%d] %s", id,
					ChangeAsString(change), k, i,
					len(rrsets), rr.String())
			}
		}
	}
}

const (
	// dirty detection methods via SOA
	// zones comparision
	DirtyViaSOA = "soa"

	// dirty method via "rrsets+data"
	DirtyViaRRsetData = "rrsets+data"
)

// Detecting a change rrset for two rrsets, we should
// expect that we have one element in a slice
func (t *TZoneState) DetectChangedRRset(rrset1 []dns.RR,
	rrset2 []dns.RR) bool {

	if len(rrset1) != len(rrset2) {
		return false
	}

	if len(rrset1) == 0 && len(rrset2) == 0 {
		return true
	}

	rrdst := make(map[string]dns.RR)
	for _, rr := range rrset1 {
		rrdst[rr.String()] = rr
	}

	rrsrc := make(map[string]dns.RR)
	for _, rr := range rrset2 {
		rrsrc[rr.String()] = rr
	}

	for k := range rrdst {
		if _, ok := rrsrc[k]; !ok {
			return false
		}
	}

	for k := range rrsrc {
		if _, ok := rrdst[k]; !ok {
			return false
		}
	}

	return true

	/*

		if len(rrset1) != 1 || len(rrset2) != 1 {
			return false
		}

		// T.B.D. we expect only one element in slice,
		// in the future we need extent key
		rr1 := rrset1[0]
		rr2 := rrset2[0]

		var b1 []byte
		var b2 []byte

		qtype1 := rr1.Header().Rrtype
		ttl1 := rr1.Header().Ttl

		switch qtype1 {
		case dns.TypeA:
			b1 = []byte(rr1.(*dns.A).A)
		case dns.TypeAAAA:
			b1 = []byte(rr1.(*dns.AAAA).AAAA)
		}

		qtype2 := rr2.Header().Rrtype
		ttl2 := rr2.Header().Ttl
		switch qtype2 {
		case dns.TypeA:
			b2 = []byte(rr2.(*dns.A).A)
		case dns.TypeAAAA:
			b2 = []byte(rr2.(*dns.AAAA).AAAA)
		}

		return bytes.Equal(b1, b2) && ttl1 == ttl2
	*/
}

// Detecting a changed set as diff betweeen snapshots S1 and S2
func (t *TZoneState) DetectChangedState(s1 *TSnapshotZone,
	s2 *TSnapshotZone) (*TChangedSetZone, error) {

	if s2 == nil || s1 == nil {
		return nil, fmt.Errorf("empty snapshot")
	}

	var changed TChangedSetZone
	changed.age = s1.timestamp.Unix() - s2.timestamp.Unix()
	changed.rrchanges = make(map[int]map[string][]dns.RR)
	changes := []int{ChangeCreate, ChangeRemove}
	for _, change := range changes {
		changed.rrchanges[change] = make(map[string][]dns.RR)
	}

	changed.created = 0
	changed.removed = 0

	// T.B.D. serial numbers change

	// detecting REMOVE and CREATE keys and UPDATE
	for k := range s1.rrsets {
		if _, ok := s2.rrsets[k]; !ok {
			v := s1.rrsets[k]
			changed.rrchanges[ChangeRemove][k] = v
			changed.removed++
			continue
		}

		// we have s1.rrsets and s2.rrsets
		// need to compare []dns.RR
		v := s1.rrsets[k]
		w := s2.rrsets[k]
		if t.DetectChangedRRset(v, w) {
			// no changes detected, skip it
			continue
		}

		changed.rrchanges[ChangeRemove][k] = v
		changed.rrchanges[ChangeCreate][k] = w

		changed.removed++
		changed.created++
	}

	for k := range s2.rrsets {
		if _, ok := s1.rrsets[k]; !ok {
			v := s2.rrsets[k]
			changed.rrchanges[ChangeCreate][k] = v
			changed.created++
		}
	}

	return &changed, nil
}

func (t *TZoneState) DetectState(p *TReceiverPlugin, snapshot *TSnapshotZone) int {
	id := "(state) (detect)"

	state := ZoneStateDirty

	if snapshot == nil {
		return state
	}

	if _, ok := t.Snapshots[t.SnapshotID]; !ok {
		p.G().L.Errorf("%s zone:'%s' snapshot:'%d' not found", id, t.Zone, t.SnapshotID)
		return state
	}

	current := t.Snapshots[t.SnapshotID]

	// we could either compare serial numbers or
	// rrsets maps (depending on configuration)
	config := p.L().AxfrTransfer

	s1 := uint32(0)
	s2 := uint32(0)

	mode := config.DirtyVia
	switch mode {
	case DirtyViaSOA:
		var err error
		// Checking current state SOA with detected
		// snapshot SOA
		s1, err = current.Serial()
		if err != nil {
			return state
		}
		s2, err = snapshot.Serial()
		if err != nil {
			return state
		}
		if s1 == s2 {
			state = ZoneStateClean
		}

		// we need always preserve dirty flag
		// as reset dirty to clean is done by
		// cooker

		if t.State == ZoneStateDirty {
			state = ZoneStateDirty
		}

		p.G().L.Debugf("%s zone:'%s' mode:'%s' ID:'%d' serials:'%d' -> '%d' %s",
			id, t.Zone, mode, t.SnapshotID, s1, s2,
			strings.ToUpper(ZoneStateAsString(state)))

	case DirtyViaRRsetData:

		sid := t.SnapshotID
		current := t.Snapshots[sid]

		changed, err := t.DetectChangedState(&current, snapshot)
		if err != nil {
			return state
		}
		changed.Dump(p, t.Zone)

		if changed.created == 0 && changed.removed == 0 {
			state = ZoneStateClean
		}

		if t.State == ZoneStateDirty {
			state = ZoneStateDirty
		}

		p.G().L.Debugf("%s zone:'%s' mode:'%s' ID:'%d' changes created:'%d' removed:'%d' %s",
			id, t.Zone, mode, t.SnapshotID, changed.created, changed.removed,
			strings.ToUpper(ZoneStateAsString(state)))

	}

	return state
}

func NewZonesState(p *TReceiverPlugin) *ZonesState {
	var z ZonesState
	z.p = p
	z.zones = make(map[string]TZoneState)
	z.locks = make(map[string]*sync.Mutex)
	return &z
}

func (z *ZonesState) DetectBlobState() int {
	id := "(zones) (state)"
	state := ZoneStateClean
	for k, s := range z.zones {
		if s.State == ZoneStateDirty {
			state = ZoneStateDirty
			z.p.G().L.Debugf("%s zone:'%s' detected as state:'%s'", id, k,
				strings.ToUpper(ZoneStateAsString(state)))
		}
	}
	return state
}

func (z *ZonesState) CreateBlob() int {
	id := "(zones) (blob)"

	counter := 0
	for k := range z.zones {

		state := z.zones[k]
		sid := state.SnapshotID

		if _, ok := state.Snapshots[sid]; !ok {
			z.p.G().L.Errorf("%s error detecting k:'%s' snapshot:'%d'", id, k, sid)
			continue
		}

		snapshot := state.Snapshots[sid]

		rcounter := 0
		age := time.Since(snapshot.timestamp).Seconds()
		z.p.G().L.Debugf("%s zone:'%s' age:'%2.2f' rrsets:'%d'", id, k, age, len(snapshot.rrsets))
		for q, rrs := range snapshot.rrsets {
			for i, rr := range rrs {

				l := dns.Len(rr)
				buf := make([]byte, l)
				_, err := dns.PackRR(rr, buf, 0, nil, false)
				if err != nil {
					z.p.G().L.Errorf("%s error packing RR k:'%s'", id, q)
					continue
				}

				wire := hex.EncodeToString(buf)
				if rcounter < DefaultDumpMaxRRsets {
					z.p.G().L.Debugf("%s zone:'%s' [%d] [%d]/[%d] L:'%d' '%s' %s", id, k,
						rcounter, i, len(rrs), l, wire, rr.String())
				}
				rcounter++
				counter++
			}
		}

		state.State = ZoneStateClean
		z.zones[k] = state
	}

	return counter
}

func (z *ZonesState) Primary(primary string) string {
	id := "(primary)"

	server := primary

	var configs []map[string]string
	if z.p.L().AxfrTransfer.Enabled {
		configs = append(configs, z.p.L().AxfrTransfer.Zones.Primary)
	}
	if z.p.L().HTTPTransfer.Enabled {
		configs = append(configs, z.p.L().HTTPTransfer.Zones.Primary)
	}

	for _, config := range configs {
		for k, v := range config {
			if k == primary {
				server = v
				break
			}
		}
	}

	if server != primary {
		z.p.G().L.Debugf("%s primary resolved as '%s' -> '%s'", id, primary, server)
	}

	return server
}

func (z *ZonesState) GetLastZoneSnapshot(zone string) *TSnapshotZone {

	state := z.zones[zone]
	sid := state.SnapshotID
	if _, ok := state.Snapshots[sid]; !ok {
		return nil
	}
	snapshot := state.Snapshots[sid]
	return &snapshot
}

func (z *ZonesState) RequestUpdate(pool *CollectorTransferPool,
	zone string, v TConfigZone) {

	id := "(zones) (update)"

	z.p.G().L.Debugf("%s requested snapshot for zone:'%s' via ['%s']",
		id, zone, strings.Join(v.Primary, ","))

	var state TZoneState
	state.Zone = zone

	config := v
	state.Config = &config

	// setting that we do not have any snapshot
	// also marking zone state as dirty
	state.SnapshotID = -1
	state.State = ZoneStateDirty
	state.SnapshotCount = DefaultSnapshotCount
	state.Snapshots = make(map[int]TSnapshotZone)

	z.zones[zone] = state

	mode := TransferModeAXFR
	if state.Config.Type == "http" {
		mode = TransferModeHTTP
	}

	// pushing job to transfer zone in AXFR mode
	// as we do not have any zone and SOA RRset
	pool.TransferJob(zone, v, mode, nil)
}

func (z *ZonesState) GetConfig(zone string) (*TConfigZone, error) {
	var zones []map[string]TConfigZone
	if z.p.L().AxfrTransfer.Enabled {
		zones = append(zones, z.p.L().AxfrTransfer.Zones.Secondary)
	}
	if z.p.L().HTTPTransfer.Enabled {
		zones = append(zones, z.p.L().HTTPTransfer.Zones.Secondary)
	}
	for _, config := range zones {
		for k, v := range config {
			if k == zone {
				conf := v
				return &conf, nil
			}
		}
	}
	return nil, fmt.Errorf("not found")
}

func (z *ZonesState) GetZonesConfigs() map[string]TConfigZone {
	id := "(zones) (configs)"

	// we need scan current configuration
	// for zones and update current zones state

	var zones []map[string]TConfigZone
	if z.p.L().AxfrTransfer.Enabled {
		zones = append(zones, z.p.L().AxfrTransfer.Zones.Secondary)
	}
	if z.p.L().HTTPTransfer.Enabled {
		zones = append(zones, z.p.L().HTTPTransfer.Zones.Secondary)
	}

	configs := make(map[string]TConfigZone)
	for _, config := range zones {
		for k, v := range config {
			if _, ok := configs[k]; ok {
				err := fmt.Errorf("zone:'%s' has more than one configuration", k)
				z.p.G().L.Errorf("%s error configure zone, err:'%s'", id, err)
				continue
			}

			configs[k] = v
		}
	}

	return configs
}

type TSnapshotsFilesState struct {
	Max   int64 `json:"max"`
	Min   int64 `json:"min"`
	Avg   int64 `json:"avg"`
	Count int64 `json:"count"`
}

func (z *ZonesState) GetSnapshotsFilesState() (*TSnapshotsFilesState, error) {
	var state TSnapshotsFilesState

	state.Max = -1
	state.Min = 2 << 32

	configs := z.GetZonesConfigs()
	for k, v := range configs {
		if !v.Enabled {
			continue
		}
		filename := GetSnapshotFilename(z.p, k)
		age := int64(GetFileAge(filename))
		if state.Min > age {
			state.Min = age
		}
		if state.Max < age {
			state.Max = age
		}

		state.Avg += age
		state.Count++
	}

	if state.Count > 0 {
		state.Avg = state.Avg / state.Count
	}
	return &state, nil
}

func (z *ZonesState) Update(pool *CollectorTransferPool) error {
	id := "(zones) (update)"
	var err error

	z.p.G().L.Debugf("%s request to update zones snapshot tiggers", id)

	configs := z.GetZonesConfigs()

	for k, v := range configs {
		if !v.Enabled {
			continue
		}
		if _, ok := z.zones[k]; !ok {
			z.RequestUpdate(pool, k, v)
			continue
		}

		// getting current state of zone, recalculating
		// SOA timer and pushing it back
		state := z.zones[k]
		sid := state.SnapshotID
		if _, ok := state.Snapshots[sid]; !ok {
			z.RequestUpdate(pool, k, v)
			continue
		}

		snapshot := state.Snapshots[sid]
		refresh, err := snapshot.Refresh()
		if err != nil {
			z.p.G().L.Errorf("%s error update zone:'%s', err:'%s'", id, k, err)
			return err
		}

		if v.Refresh > 0 {
			refresh = uint32(v.Refresh)
		}

		age := time.Since(snapshot.timestamp).Seconds()
		z.p.G().L.Debugf("%s zone:'%s' age:'%2.2f'", id, k, age)

		if uint32(age) > refresh {
			// SOA refresh expired, need renew zone, T.B.D.
			// SOA request and check serial number
			soa, err := snapshot.SOA()
			if err == nil {
				z.p.G().L.Debugf("%s zone:'%s' SOA %s", id, k, soa)
			}

			mode := TransferModeIXFR
			if state.Config.Type == "http" {
				mode = TransferModeHTTP
			}

			pool.TransferJob(k, v, mode, snapshot.soa)
		}
	}

	return err
}
