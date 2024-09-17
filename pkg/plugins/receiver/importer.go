package receiver

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"github.com/yandex/yadns-controller/pkg/plugins/offloader"
)

// importer worker implements cache import for axff
// data from servers or from file (should be set corresponded
// slice)

type ImporterWorker struct {
	p *TReceiverPlugin

	options *TConfigImporter

	// locing state table within
	// importer workers
	lock sync.Mutex
}

func NewImporterWorker(p *TReceiverPlugin, options *TConfigImporter) (*ImporterWorker, error) {
	var j ImporterWorker
	j.p = p
	j.options = options

	if len(options.File) == 0 && len(options.Zone) == 0 && len(options.Endpoint) == 0 {
		return &j, fmt.Errorf("no input sources detected, expected file or zone names")
	}

	if len(options.Zone) > 0 && len(options.Server) == 0 && len(options.Endpoint) == 0 {
		return &j, fmt.Errorf("no dns server set for zone transfer")
	}

	if len(options.File) > 0 && len(options.Zone) > 0 && len(options.Endpoint) > 0 {
		return &j, fmt.Errorf("both transfer sources defined")
	}

	return &j, nil
}

func (j *ImporterWorker) Run(ctx context.Context) error {
	id := "(importer) (worker)"
	w, ctx := errgroup.WithContext(ctx)

	w.Go(func() error {
		j.p.G().L.Debugf("%s starting worker", id)
		defer j.p.G().L.Debugf("%s worker stopped", id)

		return j.Import(ctx)
	})
	return w.Wait()
}

const (
	// we have to filter zone in two mode
	// with respect of duplications and
	// without (as bpf does not have yet
	// multiple RR)
	ImportFilterStrict = 1011

	// loosed version, no duplications check
	ImportFilterLoosed = 1012

	// skip types of fqdn to be cached
	SkipByLength = 1001
	SkipByCount  = 1002
	SkipByType   = 1003
)

// we need filter zone got iva tranfer zone containing
// only records we could push into zone and returning SOA (if any)
func (j *ImporterWorker) FilterZone(rr []dns.RR, mode int) (map[string][]dns.RR, dns.RR) {
	id := "(importer) (filter)"

	skips := make(map[int]int)
	types := []int{SkipByLength, SkipByCount, SkipByType}
	for _, t := range types {
		skips[t] = 0
	}

	rrsets := make(map[string][]dns.RR)
	var soa dns.RR
	for _, r := range rr {
		if r == nil {
			// some RR could be nil as filtered?
			continue
		}

		// need make a map for fqdn and type and validate
		// RR to be only 1 RR in RRset for type, also checking
		// the length
		h := r.Header()

		name := h.Name

		if len(j.options.Suffix) > 0 {
			name = fmt.Sprintf("%s%s.", name, j.options.Suffix)
		}

		// adding only ALLOWED types of RR
		if h.Rrtype == dns.TypeA || h.Rrtype == dns.TypeAAAA {
			if len(name) >= offloader.DefaultQnameMaxLength {
				skips[SkipByLength]++
				if skips[SkipByLength] < DefaultDumpMaxRRsets {
					j.p.G().L.Errorf("%s skip qname:'%s' as length:'%d' exceeded qname max len of '%d'",
						id, name, len(name), offloader.DefaultQnameMaxLength)
				}
				continue
			}
			key := fmt.Sprintf("%s-%s", name, dns.Type(h.Rrtype).String())
			rrsets[key] = append(rrsets[key], r)
		}

		if h.Rrtype == dns.TypeSOA {
			q := r
			soa = q
		}
	}

	frrsets := make(map[string][]dns.RR)

	for k, rrset := range rrsets {
		if len(rrset) > 1 && mode == ImportFilterStrict {
			skips[SkipByCount]++
			if skips[SkipByCount] < DefaultDumpMaxRRsets {
				j.p.G().L.Errorf("%s skip k:'%s'", id, k)
			}
			continue
		}
		frrsets[k] = rrset
	}

	j.p.G().L.Debugf("%s filter in:'%d' -> out:'%d' skips bylength:'%d' bycount:'%d'",
		id, len(rr), len(frrsets), skips[SkipByLength],
		skips[SkipByCount])

	return frrsets, soa
}

func (j *ImporterWorker) GetZoneSnapshotAXFR(zone string, options *TZoneSnapshotOptions) (*TSnapshotZone, error) {
	id := "(importer) (axfr) (snapshot)"

	var err error

	incremental := DefaultZoneSnapshotIncremental
	if options != nil {
		incremental = options.Incremental
	}

	opts := new(TransferOptions)
	opts.Mode = TransferModeAXFR
	opts.Key = options.Key

	var snapshot *TSnapshotZone
	var actions *TSnapshotActions

	if incremental {
		// if we do not have a blob with current AXFR and AXFR+IXFR
		// data gathered we need got the whole AXFR and write it
		// before making IXFR

		var err error
		snapshot, err = NewSnapshotZoneFromSnapshot(j.p, zone)
		if err == nil {

			// Reading current SOA serial from blob
			serial2, err := snapshot.Serial()
			if err != nil {
				j.p.G().L.Errorf("%s error snapshot SOA detection for zone:'%s', err:'%s'",
					id, zone, err)
				return nil, err
			}

			j.p.G().L.Debugf("%s snapshot zone:'%s' serial:'%d' is set, trying SOA request and IXFR",
				id, zone, serial2)

			if opts, err = RequestSOA(options.Server, zone); err != nil {
				j.p.G().L.Errorf("%s error SOA request zone:'%s' via server:'%s', err:'%s'",
					id, zone, options.Server, err)
				return nil, err
			}

			j.p.G().L.Debugf("%s zone:'%s' authority SOA '%d %s %s'", id, zone,
				opts.Serial, opts.Ns, opts.Mbox)
			opts.Mode = TransferModeIXFR

			j.p.G().L.Debugf("%s zone:'%s' requested serial interval:'%d -> %d'",
				id, zone, serial2, opts.Serial)

			// if serials in primary and snapshot equals
			if options.SnapshotMode == SnapshotMemoryExists {
				if serial2 == opts.Serial {
					j.p.G().L.Debugf("%s no any changes for zone:'%s' via primary:'%s' detected",
						id, zone, options.Server)

					// beware snapshot could be nil	(as no any changes occured)
					return nil, nil
				}
			}

			if options.SnapshotMode == SnapshotMemoryEmpty {
				opts.Mode = TransferModeAXFR
			}

			// making a request as IXFR setting the last seen SOA from snapshot
			opts.Serial = serial2
		}
	}

	rr, err := TransferZone(options.Server, zone, opts)
	if err != nil {
		j.p.G().L.Errorf("%s error transfering zone:'%s', err:'%s'", id, zone, err)
		return nil, err
	}
	j.p.G().L.Debugf("%s transferred zone:'%s' rrset:'%d'", id, zone, len(rr))

	mode := TransferModeUnknown

	if incremental && snapshot != nil {
		var soa dns.RR
		if soa, mode, actions, err = snapshot.ApplyIXFR(rr); err != nil {
			j.p.G().L.Errorf("%s error applying IXFR to AXFR for zone:'%s', err:'%s'", id, zone, err)
			return nil, err
		}

		if mode == TransferModeIXFR {
			// changing soa to the next serial number
			snapshot.soa = soa
			snapshot.timestamp = time.Now()
			snapshot.Dump(j.p, "axfr+ixfr", DefaultDumpMaxRRsets)
		}
	}

	if incremental && snapshot == nil {

		rrsets, soa := j.FilterZone(rr, ImportFilterLoosed)

		// need create a new snapshot from scratch
		snapshot = new(TSnapshotZone)

		snapshot.p = j.p
		snapshot.soa = soa
		snapshot.zone = zone
		snapshot.timestamp = time.Now()
		snapshot.rrsets = rrsets

		snapshot.Dump(j.p, "axfr", DefaultDumpMaxRRsets)

		// first AXFR
		mode = TransferModeAXFR
	}

	// checking if received ixfr is actually axfr or ixfr,
	// if section is SectionUnknown it does mean that there's no
	// any IXFR sections and rr is AXFR and snapshot should
	// be replaced by with AXFR
	if mode == TransferModeAXFR && snapshot != nil {

		rrsets, soa := j.FilterZone(rr, ImportFilterLoosed)

		// here we have already snapshot
		snapshot.soa = soa
		snapshot.timestamp = time.Now()

		// removing all current rrsets
		snapshot.RemoveRRsets()

		// replacing map rrset with new data of ixfr
		// map[string][]dns.RR vs []dns.RR
		snapshot.rrsets = rrsets

		snapshot.Dump(j.p, "axfr+fallback", DefaultDumpMaxRRsets)
	}

	imports := &TImportActions{mode: mode, zone: zone, actions: actions}
	snapshot.imports = imports

	return snapshot, nil
}

func (j *ImporterWorker) GetZoneSnapshotHTTP(ctx context.Context, source string,
	options *TZoneSnapshotOptions) (*TSnapshotZone, error) {
	id := "(importer) (http) (snapshot)"

	var err error

	var snapshot *TSnapshotZone

	switch options.Source {
	case SourceFile:
		filename := strings.TrimPrefix(options.Server, "file:///")
		j.p.G().L.Debugf("%s request snapshot zone:'%s' server:'%s' filename:'%s'", id,
			source, options.Server, filename)
		snapshot, err = NewSnapshotZoneFromFile(j.p, filename, source)
	case SourceHTTP:
		snapshot, err = NewSnapshotZoneFromEndpoint(j.p, ctx,
			[]string{options.Server}, source)
	}
	if err != nil {
		j.p.G().L.Errorf("%s error import source:'%s' as snapshot via options:'%d', err:'%s'",
			id, source, options.Source, err)
		return nil, err
	}
	snapshot.Dump(j.p, "axfr", DefaultDumpMaxRRsets)

	incremental := DefaultZoneSnapshotIncremental
	if options != nil {
		incremental = options.Incremental
	}

	zone := snapshot.zone
	if snapshot.soa != nil {
		serial, _ := snapshot.Serial()
		j.p.G().L.Debugf("%s zone:'%s' serial:'%d' derived authority SOA '%s'",
			id, zone, serial, snapshot.soa.String())
	}

	mode := TransferModeAXFR

	var actions *TSnapshotActions

	if incremental {
		// as for file we do have IXFR data, so we need
		// generate them
		blob, err := NewSnapshotZoneFromSnapshot(j.p, zone)
		if err == nil {
			// we have blob of some previous version, we
			// need calculate a changed set
			var state TZoneState
			changed, err := state.DetectChangedState(blob, snapshot)
			if err != nil {
				j.p.G().L.Errorf("%s error detect changed state source:'%s' zone:'%s', err:'%s'",
					id, source, zone, err)
				return nil, err
			}
			changed.Dump(j.p, fmt.Sprintf("%s changes", zone))

			j.p.G().L.Debugf("%s zone:'%s' changes created:'%d' removed:'%d'",
				id, zone, changed.created, changed.removed)

			mode = TransferModeIXFR
			actions = changed.AsActions()
		}

		if blob == nil {
			// if we do not have current blob we
			// need make a full reload
			mode = TransferModeAXFR
		}

		snapshot.imports = &TImportActions{mode: mode, zone: zone, actions: actions}
		return snapshot, nil
	}

	return nil, fmt.Errorf("full sync axfr is not implemented")
}

type TUpdateZoneStateOptions struct {
	Incremental bool

	Server string

	Key string
}

const (
	SnapshotMemoryEmpty  = 1001
	SnapshotMemoryExists = 1002
)

func (j *ImporterWorker) UpdateZoneState(ctx context.Context, states *ZonesState, source int,
	zone string, config *TConfigZone, options *TUpdateZoneStateOptions) error {

	id := "(importer) (state)"

	var state TZoneState
	state.Config = config
	state.SnapshotID = -1
	state.State = ZoneStateDirty
	state.SnapshotCount = DefaultSnapshotCount
	state.Snapshots = make(map[int]TSnapshotZone)

	if _, ok := states.locks[zone]; !ok {
		var lock sync.Mutex

		j.lock.Lock()
		states.locks[zone] = &lock
		j.lock.Unlock()
	}

	states.locks[zone].Lock()
	defer states.locks[zone].Unlock()

	// if we do not have any snapshot zone requested
	// we need set snapshot mode
	mode := SnapshotMemoryEmpty
	if states.GetLastZoneSnapshot(zone) != nil {
		mode = SnapshotMemoryExists
	}

	// Additional change as we could pump snapshot of zones
	// into memory if no any snapshot detected
	if mode == SnapshotMemoryEmpty {
		options := j.p.L().Options
		startup := options.Snapshots.StartupValidInterval

		if startup > 0 {
			// if we have startup timer for snapshots for
			// cold start. Try to get them
			j.p.G().L.Debugf("%s cold startup timer:'%d' for zone:'%s'",
				id, startup, zone)

			filename := GetSnapshotFilename(j.p, zone)
			age := GetFileAge(filename)

			j.p.G().L.Debugf("%s cold startup zone:'%s' snapshot:'%s' age:'%2.2f'",
				id, zone, filename, age)

			if age < float64(startup) {
				snapshot, err := NewSnapshotZoneFromSnapshot(j.p, zone)
				if snapshot != nil && err == nil {

					// we have ready snapshot of age less than startup,
					// assuming that all zones in bpf.Map and files are
					// the same, if not, we have verifier process to
					// indicate the difference

					snapshot.imports = &TImportActions{
						mode:    TransferModeNONE,
						zone:    zone,
						actions: nil,
					}

					state.SnapshotID = (state.SnapshotID + 1) % state.SnapshotCount
					state.Snapshots[state.SnapshotID] = *snapshot
					state.Zone = zone

					states.zones[zone] = state

					return nil
				}
			}
		}
	}

	opts := TZoneSnapshotOptions{
		Incremental:  options.Incremental,
		Source:       source,
		Server:       options.Server,
		Key:          options.Key,
		SnapshotMode: mode,
	}

	var err error
	var snapshot *TSnapshotZone
	switch source {
	case SourceHTTP, SourceFile:
		// checking if zone has file:// prefix
		if strings.HasPrefix(opts.Server, "file://") {
			opts.Source = SourceFile
		}
		snapshot, err = j.GetZoneSnapshotHTTP(ctx, zone, &opts)
	case SourceAXFR:
		snapshot, err = j.GetZoneSnapshotAXFR(zone, &opts)
	}

	if err != nil {
		j.p.G().L.Errorf("%s error getting snapshot zone:'%s', err:'%s'",
			id, zone, err)
		return err
	}

	if snapshot != nil {
		state.SnapshotID = (state.SnapshotID + 1) % state.SnapshotCount
		state.Snapshots[state.SnapshotID] = *snapshot

		zone := snapshot.imports.zone
		state.Zone = zone

		// calculating state of zone w.r.t of
		// algorithm choosen and current and previous
		// snapshots
		state.State = state.DetectState(j.p, snapshot)

		states.zones[zone] = state

		j.p.G().L.Debugf("%s ixfr snapshot updated zone:'%s' rrsets:'%d'",
			id, zone, len(snapshot.rrsets))
	}

	if snapshot == nil {
		// it means that there's no any changes in zone, so we need
		// to push state into IXFR mode (incremental with zero
		// changes)

		if _, ok := states.zones[zone]; !ok {
			err = fmt.Errorf("no snapshot detected")
			j.p.G().L.Errorf("%s error detecting current snapshot zone:'%s', err:'%s'",
				id, zone, err)
			return err
		}

		state := states.zones[zone]
		sid := state.SnapshotID
		if sid == -1 {
			err := fmt.Errorf("no valid snapshot for zone:'%s' found", zone)
			j.p.G().L.Errorf("%s error cooking, err:'%s'", id, err)
			return err
		}

		snapshot := state.Snapshots[sid]
		imports := snapshot.imports
		imports.mode = TransferModeNONE

		snapshot.imports = imports
		state.Snapshots[sid] = snapshot
		states.zones[zone] = state

		j.p.G().L.Debugf("%s axfr none changes via ixfr snapshot updated zone:'%s' rrsets:'%d'",
			id, zone, len(snapshot.rrsets))
	}

	return nil
}

func (j *ImporterWorker) Import(ctx context.Context) error {
	id := "(importer)"

	var err error

	t0 := time.Now()
	states := NewZonesState(j.p)

	// Detecting which source should be processed, axfr via
	// dns transfers or a list of zones

	// Validating source files and skipping RR that should
	// not be placed in cache

	// Import mode means that we place all records ASIS without
	// RRset synchronization. Or we could clean before all
	// RRsets and import all back (--clean option?)

	incremental := j.options.Incremental

	t := SourceFile
	endpoint := ""
	if len(j.options.Endpoint) > 0 {
		t = SourceHTTP
		endpoint = j.options.Endpoint[0]
	}
	if len(j.options.Server) > 0 {
		t = SourceAXFR
		endpoint = j.options.Server
	}

	defaultconfig := CreateDefaultConfigZone([]string{j.options.Server})

	var sources []string
	sources = append(sources, j.options.Zone...)
	sources = append(sources, j.options.File...)

	// updating state with respect of default configuration
	for _, source := range sources {
		options := TUpdateZoneStateOptions{
			Incremental: incremental,
			Server:      endpoint,
			Key:         j.options.Key,
		}
		if err = j.UpdateZoneState(ctx, states, t, source,
			&defaultconfig, &options); err != nil {

			j.p.G().L.Errorf("%s error updating snapshot source:'%s', err:'%s'",
				id, source, err)
			return err
		}
	}

	var options TConfigCooker
	options.Dryrun = j.options.Dryrun

	cooker, _ := NewCookerWorker(j.p, &options, states)
	if err = cooker.Cook(ctx, 0, j.options.Dryrun); err != nil {
		j.p.G().L.Errorf("%s error cooking snapshots, err:'%s'", id, err)
		return err
	}

	j.p.G().L.Debugf("%s finished in '%s'", id, time.Since(t0))
	return err
}
