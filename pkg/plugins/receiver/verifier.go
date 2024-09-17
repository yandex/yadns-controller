package receiver

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

const (
	// default verifier inrterval in seconds
	DefaultVerifierInterval = 120 * time.Second
)

type VerifierWorker struct {
	p *TReceiverPlugin

	options *TConfigVerifier

	// ref to zones state gathered by recevier
	zones *ZonesState
}

func NewVerifierWorker(p *TReceiverPlugin, zones *ZonesState) (*VerifierWorker, error) {

	var j VerifierWorker
	j.p = p
	j.zones = zones

	return &j, nil
}

func (j *VerifierWorker) CompareSnapshots(src map[string][]dns.RR,
	dst map[string][]dns.RR) (*TVerifyResult, *TChangedSetZone, error) {

	id := "(verifier) (snapshots)"
	var err error

	var result TVerifyResult
	result.Total = 0
	result.Verified = 0

	var changed TChangedSetZone
	changed.age = time.Now().Unix()

	changed.rrchanges = make(map[int]map[string][]dns.RR)
	changes := []int{ChangeCreate, ChangeRemove}
	for _, change := range changes {
		changed.rrchanges[change] = make(map[string][]dns.RR)
	}
	changed.created = 0
	changed.removed = 0

	// trying to linear slices
	srcp := make(map[string]dns.RR)
	dstp := make(map[string]dns.RR)

	for _, vv := range src {
		for _, v := range vv {
			result.Total++
			srcp[v.String()] = v
		}
	}

	for _, vv := range dst {
		for _, v := range vv {
			result.Verified++
			dstp[v.String()] = v
		}
	}

	for k, rr := range srcp {
		if _, ok := dstp[k]; !ok {
			result.Missed++
			if result.Missed < DefaultDumpMaxRRsets*10 {
				j.p.G().L.Debugf("%s missed on dst k:'%s' %s", id, k, rr.String())
			}

			changed.rrchanges[ChangeCreate][k] =
				append(changed.rrchanges[ChangeCreate][k], rr)
			changed.created++
		}
	}

	for k, rr := range dstp {
		if _, ok := srcp[k]; !ok {
			result.Unexpected++
			if result.Unexpected < DefaultDumpMaxRRsets*10 {
				j.p.G().L.Debugf("%s unexpected on dst k:'%s' %s", id, k, rr.String())
			}

			changed.rrchanges[ChangeRemove][k] =
				append(changed.rrchanges[ChangeRemove][k], rr)
			changed.created++
		}
	}

	j.p.G().L.Debugf("%s verifier result %s", id, result.AsString())

	changed.Dump(j.p, "(verifier) (changes)")

	return &result, &changed, err
}

func (j *VerifierWorker) VerifyZone(ctx context.Context, zones []string,
	server string) (*TVerifyResult, error) {

	id := "(verifier) (blob)"
	var err error
	t0 := time.Now()

	max := 20

	var verify TVerifyResult

	mode := TransferModeAXFR
	for _, zone := range zones {

		opts := new(TransferOptions)
		opts.Mode = mode

		rr, err := TransferZone(server, zone, opts)
		if err != nil {
			j.p.G().L.Errorf("%s error transfering zone:'%s', err:'%s'", id, zone, err)
			return nil, err
		}
		j.p.G().L.Debugf("%s transferred zone:'%s' rrset:'%d'", id, zone, len(rr))

		var config TConfigImporter
		config.Zone = append(config.Zone, zone)
		config.Server = server
		importer, err := NewImporterWorker(j.p, &config)

		if err != nil {
			j.p.G().L.Errorf("%s error importing zone:'%s' via primary:'%s' err:'%s'",
				id, zone, server, err)
			return nil, err
		}

		rrsets, soa := importer.FilterZone(rr, ImportFilterLoosed)

		var snap TSnapshotZone

		snap.p = j.p
		snap.soa = soa
		snap.zone = zone
		snap.timestamp = time.Now()
		snap.rrsets = rrsets

		snap.Dump(j.p, "axfr", max)

		// getting rrsets from blob
		filename := GetSnapshotFilename(j.p, zone)

		blob, err := NewSnapshotZoneFromFile(j.p, filename, zone)
		if err != nil {
			j.p.G().L.Errorf("%s error making snapshot from blob for zone:'%s',  err:'%s'",
				id, zone, err)
			return nil, err
		}

		j.p.G().L.Debugf("%s importing snapshot from blob:'%s' zone:'%s' rrsets:'%d'",
			id, filename, zone, len(blob.rrsets))

		blob.Dump(j.p, "blob", max)

		zresult, _, err := j.CompareSnapshots(snap.rrsets, blob.rrsets)
		if err != nil {
			j.p.G().L.Errorf("%s error compare blob for zone:'%s',  err:'%s'",
				id, zone, err)
			return nil, err
		}

		verify.Total += zresult.Total
		verify.Verified += zresult.Verified
		verify.Missed += zresult.Missed
		verify.DifferOnTTL += zresult.DifferOnTTL
		verify.DifferOnIP += zresult.DifferOnIP
		verify.Unexpected += zresult.Unexpected
	}

	j.p.G().L.Debugf("%s finished in '%s'", id, time.Since(t0))
	return &verify, err
}

func (j *VerifierWorker) VerifyBlob(ctx context.Context, options *VerifyOptions) (*TVerifyResult, error) {
	id := "(verifier) (verify) (blob)"
	var err error

	t0 := time.Now()
	j.p.G().L.Debugf("%s request to verify snapshots and blob", id)

	var verify TVerifyResult

	zones := NewZonesState(j.p)
	configs := zones.GetZonesConfigs()
	for k, v := range configs {
		if !v.Enabled {
			continue
		}
		if v.Type != TransferTypeAXFR {
			continue
		}

		if len(v.Primary) == 0 {
			continue
		}

		server := v.Primary[0]

		result, err := j.VerifyZone(ctx, []string{k}, server)
		if err != nil {
			j.p.G().L.Errorf("%s error verifying zone:'%s', err:'%s'", id, k, err)
			return nil, err
		}

		verify.Total += result.Total
		verify.Verified += result.Verified
		verify.Missed += result.Missed
		verify.DifferOnTTL += result.DifferOnTTL
		verify.DifferOnIP += result.DifferOnIP
		verify.Unexpected += result.Unexpected
	}

	/*
		if j.monitor != nil {
			j.monitor.PushIntMetric(MetricsVerifyTotal, int64(verify.Total))
			j.monitor.PushIntMetric(MetricsVerifyVerified, int64(verify.Verified))
			j.monitor.PushIntMetric(MetricsVerifyMissed, int64(verify.Missed))
			j.monitor.PushIntMetric(MetricsVerifyDifferOnTTL, int64(verify.DifferOnTTL))
			j.monitor.PushIntMetric(MetricsVerifyDifferOnIP, int64(verify.DifferOnIP))
			j.monitor.PushIntMetric(MetricsVerifyUnexpected, int64(verify.Unexpected))
		}
	*/

	j.p.G().L.Debugf("%s result %s", id, verify.AsString())
	j.p.G().L.Debugf("%s finished in %s", id, time.Since(t0))

	return &verify, err
}

func (j *VerifierWorker) Run(ctx context.Context) error {
	id := "(verifier) (worker)"
	w, ctx := errgroup.WithContext(ctx)

	verifier := j.p.L().Verifier

	if verifier.Enabled {
		// we have to periodically check zones state
		// and determine if need to make new blob and
		// file snapshot for it
		w.Go(func() error {
			defer j.p.G().L.Debugf("%s verifier worker stopped", id)

			// starting cooker check and make blob
			return j.TickVerifier(ctx)
		})

		// the second thase to verify zones recevied from AXFR
		// and blob received
		w.Go(func() error {
			defer j.p.G().L.Debugf("%s verifier blob worker stopped", id)

			// starting cooker check and make blob
			return j.TickBlobVerifier(ctx)
		})
	}

	return w.Wait()
}

func (j *VerifierWorker) TickBlobVerifier(ctx context.Context) error {
	id := "(verifier) (blob) (tick)"

	interval := DefaultVerifierInterval
	verifier := j.p.L().Verifier
	if verifier.Interval > 0 {
		interval = time.Duration(rand.Intn(verifier.Interval)+verifier.Interval) * time.Second
	}

	j.p.G().L.Debugf("%s starting verify worker each interval:'%s' seconds", id, interval)

	counter := 0
	timer := time.NewTicker(interval)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			counter++
			j.p.G().L.Debugf("%s request to blob verify", id)

			options := VerifyOptions{Dryrun: true}
			result, err := j.VerifyBlob(ctx, &options)
			if err != nil {
				j.p.G().L.Errorf("%s error blob verify snapshots and bpf maps, err:'%s'", id, err)
				continue
			}

			// checking result thresholds limits
			j.p.G().L.DumpBytes(id, result.AsJSON(), 0)

		case <-ctx.Done():
			j.p.G().L.Debugf("%s context stop on blob verifier", id)
			return ctx.Err()
		}
	}
}

func (j *VerifierWorker) TickVerifier(ctx context.Context) error {
	id := "(verifier) (tick)"

	interval := DefaultVerifierInterval
	verifier := j.p.L().Verifier
	if verifier.Interval > 0 {
		interval = time.Duration(rand.Intn(verifier.Interval)+verifier.Interval) * time.Second
	}

	j.p.G().L.Debugf("%s starting verify worker each interval:'%s' seconds", id, interval)

	counter := 0
	timer := time.NewTicker(interval)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			counter++
			j.p.G().L.Debugf("%s request to verify", id)

			options := VerifyOptions{Dryrun: true}
			result, err := j.Verify(&options)
			if err != nil {
				j.p.G().L.Errorf("%s error verify snapshots and bpf maps, err:'%s'", id, err)
				continue
			}

			// checking result thresholds limits
			j.p.G().L.DumpBytes(id, result.AsJSON(), 0)

		case <-ctx.Done():
			j.p.G().L.Debugf("%s context stop on verifier", id)
			return ctx.Err()
		}
	}
}

type VerifyOptions struct {
	Dryrun bool
}

func (j *VerifierWorker) Verify(options *VerifyOptions) (*TVerifyResult, error) {
	id := "(verifier) (verify)"
	var err error

	t0 := time.Now()
	j.p.G().L.Debugf("%s request to verify snapshots and bpf maps", id)

	// creating the whole snapshot from zone
	// current versions

	var snapshot TSnapshotZone
	snapshot.p = j.p
	snapshot.timestamp = time.Now()
	snapshot.rrsets = make(map[string][]dns.RR)

	for z, state := range j.zones.zones {

		// getting current snapshot
		sid := state.SnapshotID
		if _, ok := state.Snapshots[sid]; !ok {
			err = fmt.Errorf("zone:'%s' state not found", z)
			j.p.G().L.Debugf("%s error verify zone:'%s', err:'%s'", id, z, err)
			return nil, err
		}

		current := state.Snapshots[sid]

		for k, v := range current.rrsets {
			snapshot.rrsets[k] = append(snapshot.rrsets[k], v...)
		}

		j.p.G().L.Debugf("%s z:'%s' rrsets:'%d' merged", id, z, len(current.rrsets))
	}

	snapshot.Dump(j.p, "axfr", DefaultDumpMaxRRsets)
	j.p.G().L.Debugf("%s total rrsets:'%d' merged", id, len(snapshot.rrsets))

	var result *TVerifyResult
	var changed *TChangedSetZone
	if result, changed, err = snapshot.VerifyMap(); err != nil {
		j.p.G().L.Errorf("%s error verifying map , err:'%s'", id, err)
		return nil, err
	}

	// if we have changes in changed set try to apply them
	if changed != nil && changed.created+changed.removed > 0 {

		actions := changed.AsActions()
		mode := TransferModeIXFR

		var r *TSyncMapResult
		if r, err = snapshot.SyncMap(mode, actions, options.Dryrun); err != nil {
			j.p.G().L.Errorf("%s error syncing map, err:'%s'",
				id, err)
			return result, err
		}
		j.p.G().L.Debugf("%s ixfr sync map '%s'", id, r.AsString())
	}

	j.p.G().L.Debugf("%s result %s", id, result.AsString())
	j.p.G().L.Debugf("%s finished in %s", id, time.Since(t0))
	return result, err
}

func (j *VerifierWorker) Stop() {
	id := "(verifier) (stop)"
	j.p.G().L.Debugf("%s cleaning some verifier data", id)

	// T.B.D. to do something to shutdown instance
}
