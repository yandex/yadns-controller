package receiver

import (
	"context"
	"fmt"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
)

const (
	// default cooker interval in seconds
	DefaultCookerInterval = 70 * time.Second
)

// cooker cooks data received by receiver into
// blob, keeping them in snapshot directory if
// enabled, later such snapshot could be imported
type CookerWorker struct {
	p *TReceiverPlugin

	options *TConfigCooker

	// ref to zones state gathered by recevier
	zones *ZonesState

	verifier *VerifierWorker
}

func NewCookerWorker(p *TReceiverPlugin, options *TConfigCooker,
	zones *ZonesState) (*CookerWorker, error) {

	var j CookerWorker
	j.p = p
	j.options = options
	j.zones = zones

	return &j, nil
}

func (j *CookerWorker) Run(ctx context.Context) error {
	id := "(cooker) (worker)"
	w, ctx := errgroup.WithContext(ctx)

	cooker := j.p.L().Cooker
	if cooker.Enabled {

		// we have to periodically check zones state
		// and determine if need to make new blob and
		// file snapshot for it
		w.Go(func() error {
			defer j.p.G().L.Debugf("%s cooker worker stopped", id)

			// starting cooker check and make blob
			return j.TickCooker(ctx)
		})
	}

	return w.Wait()
}

const (
	CookerLock   = 1001
	CookerNoLock = 1002
)

func (j *CookerWorker) CookIncrementZone(ctx context.Context,
	zone string, mode int) (*TSyncMapResult, error) {

	id := "(cooker)"

	if mode == CookerLock {
		if _, ok := j.zones.locks[zone]; !ok {
			return nil, fmt.Errorf("no lock for zone available")
		}

		t0 := time.Now()
		j.p.G().L.Debugf("%s request to lock zone:'%s'...", id, zone)
		j.zones.locks[zone].Lock()
		defer j.zones.locks[zone].Unlock()
		j.p.G().L.Debugf("%s zone:'%s' locked in '%s' OK", id, zone, time.Since(t0))
	}

	if _, ok := j.zones.zones[zone]; !ok {
		return nil, fmt.Errorf("no zone available")
	}

	// Here we wait for lock on zone and lock could be
	// acquired as context is cancelled, check it
	if ctx.Err() != nil {
		err := fmt.Errorf("context cancelled waiting lock zone:'%s'", zone)
		j.p.G().L.Errorf("%s error increment zone zone:'%s', err:'%s'", id, zone, err)
		return nil, err
	}

	state := j.zones.zones[zone]

	sid := state.SnapshotID
	snapshot := state.Snapshots[sid]

	j.p.G().L.Debugf("%s ixfr sync map zone:'%s' sid:'%d'", id, zone, sid)

	actions := snapshot.imports

	// Here we have a full snapshot and we could import it
	// in bpf map into two modes: (1) incremental if we have
	// TransferModeIXFR (2) full sync if we have
	// TransferModeAXFR, skip with error in other cases

	// sync map could run in both modes: AXFR and IXFR, for
	// IXFR it uses generated before actions data
	r, err := snapshot.SyncMap(actions.mode, actions.actions, j.options.Dryrun)

	if err != nil {
		j.p.G().L.Errorf("%s error syncing map zone:'%s', err:'%s'",
			id, zone, err)
		return nil, err
	}

	return r, nil
}

func (j *CookerWorker) Cook(ctx context.Context, index int, dryrun bool) error {
	id := fmt.Sprintf("(cooker) (cook) [%d]", index)
	var err error

	t0 := time.Now()

	j.p.G().L.Debugf("%s request to cook zones snapshot into map", id)
	if j.zones == nil {
		err := fmt.Errorf("no zones states found")
		j.p.G().L.Errorf("%s error cooking, err:'%s'", id, err)
		return err
	}

	states := j.zones

	// if at least one zone is AXFR w need to sync all
	// zones as AXFR (as in AXFR mode we need first
	// create total rrset and sync it with bpf.Map
	mode := TransferModeIXFR
	counter := 0
	for zone, state := range states.zones {
		sid := state.SnapshotID
		if sid == -1 {
			err := fmt.Errorf("no valid snapshot for zone:'%s' found", zone)
			j.p.G().L.Errorf("%s error cooking, err:'%s'", id, err)
			return err
		}

		snapshot := state.Snapshots[sid]
		imports := snapshot.imports
		if imports.mode == TransferModeAXFR {
			mode = TransferModeAXFR
		}

		j.p.G().L.Debugf("%s state [%d]/[%d] zone:'%s' as '%s'", id, counter, len(states.zones),
			zone, TransferModeAsString(imports.mode))

		counter++
	}

	j.p.G().L.Debugf("%s map zones:'%d' state detected as '%s'", id, len(states.zones),
		TransferModeAsString(mode))

	var result *TSyncMapResult

	switch mode {
	case TransferModeAXFR:

		// fallback to AXFR mode for all snapshot zones
		// as we need create all zones blob and sync it
		// with bpf.Map
		j.p.G().L.Debugf("%s fallback to AXFR", id)

		// need create a new snapshot from scratch
		var snapshot TSnapshotZone
		snapshot.p = j.p
		snapshot.timestamp = time.Now()
		snapshot.rrsets = make(map[string][]dns.RR)

		// creating new snapshot with all AXFR rrsets
		for _, state := range states.zones {
			sid := state.SnapshotID
			snap := state.Snapshots[sid]
			for k, v := range snap.rrsets {
				snapshot.rrsets[k] = append(snapshot.rrsets[k], v...)
			}
		}
		snapshot.Dump(j.p, "axfr", DefaultDumpMaxRRsets)

		if result, err = snapshot.SyncMap(mode, nil, j.options.Dryrun); err != nil {
			j.p.G().L.Errorf("%s error syncing blob AXFR map, err:'%s'", id, err)
			return err
		}

	case TransferModeIXFR:

		result = new(TSyncMapResult)

		// We have all states snapshots and actions ready
		// need to apply all changes (IXFR modes)
		for zone := range states.zones {
			r, err := j.CookIncrementZone(ctx, zone, CookerLock)
			if err != nil {
				j.p.G().L.Errorf("%s error syncing map zone:'%s', err:'%s'",
					id, zone, err)
				return err
			}
			result.Created += r.Created
			result.Removed += r.Removed
		}

		//j.monitor.PushIntMetric(MetricsCookerSyncCreated, int64(result.Created))
		//j.monitor.PushIntMetric(MetricsCookerSyncRemoved, int64(result.Removed))
	}

	for zone, state := range states.zones {
		sid := state.SnapshotID
		snapshot := state.Snapshots[sid]

		if err = snapshot.WriteSnapshotZone(j.options.Dryrun); err != nil {
			j.p.G().L.Errorf("%s error writing blob for zone:'%s', err:'%s'",
				id, zone, err)
			return err
		}
	}

	j.p.G().L.Debugf("%s sync map result '%s'", id, result.AsString())

	verifier := j.p.L().Verifier
	if verifier.VerifyOnCook {
		// if enabled verify check after cooking
		// we need to run it

		if j.verifier != nil {
			options := VerifyOptions{Dryrun: false}
			result, err := j.verifier.Verify(&options)
			if err != nil {
				j.p.G().L.Errorf("%s error verify snapshots and bpf maps, err:'%s'", id, err)
				return err
			}

			/*
				j.monitor.PushIntMetric(MetricsCookerVerifyTotal, int64(result.Total))
				j.monitor.PushIntMetric(MetricsCookerVerifyVerified, int64(result.Verified))
				j.monitor.PushIntMetric(MetricsCookerVerifyMissed, int64(result.Missed))
				j.monitor.PushIntMetric(MetricsCookerVerifyDifferOnTTL, int64(result.DifferOnTTL))
				j.monitor.PushIntMetric(MetricsCookerVerifyDifferOnIP, int64(result.DifferOnIP))
				j.monitor.PushIntMetric(MetricsCookerVerifyUnexpected, int64(result.Unexpected))
			*/
			// checking result thresholds limits
			j.p.G().L.DumpBytes(id, result.AsJSON(), 0)
		}
	}

	elapsed := time.Since(t0)
	/*
		j.monitor.PushIntMetric(MetricsCookerCookTime,
			elapsed.Milliseconds())
	*/
	j.p.G().L.Debugf("%s finished in '%s'", id, elapsed)

	return err
}

func (j *CookerWorker) TickCooker(ctx context.Context) error {
	id := "(cooker) (tick)"

	interval := DefaultCookerInterval
	cooker := j.p.L().Cooker
	if cooker.Interval > 0 {
		interval = time.Duration(cooker.Interval) * time.Second
	}

	counter := 0
	timer := time.NewTicker(interval)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			counter++

			err := j.Cook(ctx, counter, cooker.Dryrun)
			if err != nil {
				j.p.G().L.Errorf("%s error cooking data, err:'%s'", id, err)
				continue
			}

			// checking aggregate state for BLOB if state
			// is dirty we need create a BLOB
			if j.zones.DetectBlobState() == ZoneStateDirty {
				counter := j.zones.CreateBlob()
				j.p.G().L.Debugf("%s blob rrset count received:'%d'",
					id, counter)
			}

		case <-ctx.Done():
			j.p.G().L.Debugf("%s context stop on cooker", id)
			return ctx.Err()
		}
	}
}

func (j *CookerWorker) Stop() {
	id := "(cooker) (stop)"
	j.p.G().L.Debugf("%s cleaning some cooker data", id)

	// T.B.D. to do something to shutdown instance
}
