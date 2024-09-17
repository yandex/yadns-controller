package receiver

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// collector transfer options
type CollectorTransferOptions struct {
	Dryrun bool `json:"dryrun"`

	// number of workers to run
	Count int `json:"count"`
}

// collector transfer pool
type CollectorTransferPool struct {
	p *TReceiverPlugin

	// job channels in both directions
	jobs    chan CollectorJob
	results chan CollectorResult

	// zones state
	zones *ZonesState

	options *CollectorTransferOptions

	// channel to send done request in
	// event waiting cycle
	done chan struct{}
}

const (
	// zone could be transferred via TSIG
	DefaultEmptyTSIG = ""

	// job to transfer zone
	ClassJobTransfer = 1011

	// job to process notifu received
	ClassJobNotifier = 1012
)

type CollectorJob struct {
	ID int64 `json:"ID"`

	ClassJob int `json:"class-job"`

	// zone to operate (transfer, dump)
	Zone string `json:"zone"`

	// configuration of zone
	Config TConfigZone `json:"config"`

	// transfer options AXFR and IXFR
	Options *TransferOptions

	// ref: current state of zones fetched
	Zones *ZonesState
}

func (j *CollectorJob) String() string {
	return fmt.Sprintf("id:'%d'", j.ID)
}

type CollectorResult struct {
	Job *CollectorJob `json:"job"`

	ID int64 `json:"id"`

	// error for collector result or nil
	// if all is okey
	Error error `json:"error"`

	// processed time
	Processed int64 `json:"processed"`
}

const (
	// possible configured type of zone
	// transfer axfr and http
	TransferTypeAXFR = "axfr"

	// http also could mean file (if primary
	// has file:// prefix
	TransferTypeHTTP = "http"

	// by default we do not use TSIG
	DefaultTSIGKey = ""
)

func (j *CollectorJob) execute(p *TReceiverPlugin, ctx context.Context,
	index int, options *CollectorTransferOptions,
	job CollectorJob) CollectorResult {

	id := "(collector) (job)"
	t0 := time.Now()

	var result CollectorResult
	result.ID = time.Now().UnixNano()
	result.Job = j

	switch job.ClassJob {
	case ClassJobTransfer:

		zone := job.Zone
		for _, primary := range job.Config.Primary {

			p.G().L.Debugf("%s worker:'%d' importing zone:'%s' via primary:'%s'",
				id, index, zone, primary)

			// need resolve primary (if is has some alias)
			server := job.Zones.Primary(primary)

			defaultconfig := job.Config

			t := SourceUnknown
			var opts TConfigImporter
			switch job.Config.Type {
			case TransferTypeHTTP:
				// also could be SourceFILE as we have server
				// be prefixed with http://
				t = SourceHTTP
				opts.Endpoint = append(opts.Endpoint, server)

			case TransferTypeAXFR:
				t = SourceAXFR
				opts.Server = server
				opts.Zone = append(opts.Zone, zone)
			}

			importer, err := NewImporterWorker(p, &opts)
			if err != nil {
				result.Error = err
				p.G().L.Errorf("%s error importing zone:'%s' via primary:'%s' err:'%s'",
					id, zone, server, err)
				return result
			}

			options := TUpdateZoneStateOptions{
				Incremental: p.L().Options.Incremental,
				Server:      server,
				Key:         DefaultTSIGKey,
			}

			err = importer.UpdateZoneState(ctx, job.Zones, t, zone,
				&defaultconfig, &options)
			if err != nil {
				p.G().L.Errorf("%s error updating snapshot source:'%s', err:'%s'",
					id, server, err)
				result.Error = err
				return result
			}
		}
	}

	result.Processed = time.Since(t0).Milliseconds()

	//        monitor.PushIntMetric(fmt.Sprintf("%s-%s", MetricsReceiverZoneTime,
	//                GetSnapshotID(job.Zone)), result.Processed)

	p.G().L.Debugf("%s worker:'%d' executed job %s in '%d' ms",
		id, index, j.String(), result.Processed)

	return result
}

func NewCollectorTransferPool(p *TReceiverPlugin, options *CollectorTransferOptions) *CollectorTransferPool {

	count := DefaultTransferPoolWorkers
	if options != nil {
		count = options.Count
	}

	return &CollectorTransferPool{
		p: p,
		// some options to override default
		options: options,
		jobs:    make(chan CollectorJob, count),
		results: make(chan CollectorResult, count),
		done:    make(chan struct{}),
	}
}

func (t *CollectorTransferPool) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for i := 0; i < t.options.Count; i++ {
		wg.Add(1)
		go t.Worker(ctx, i, &wg, t.jobs, t.results)
	}
	wg.Wait()
	close(t.done)
	close(t.results)
}

func (t *CollectorTransferPool) Worker(ctx context.Context, index int, wg *sync.WaitGroup,
	jobs <-chan CollectorJob, results chan<- CollectorResult) {

	id := "(collector) (worker)"
	defer wg.Done()
	for {
		select {
		case job, ok := <-jobs:
			if !ok {
				t.p.G().L.Debugf("%s error on worker channel index '%d'", id, index)
				results <- CollectorResult{Error: ctx.Err()}
				return
			}

			// run job and receive a result from execution
			// context as collector job result
			results <- job.execute(t.p, ctx, index, t.options, job)

		case <-ctx.Done():
			t.p.G().L.Debugf("%s stopped worker on index '%d'", id, index)
			results <- CollectorResult{Error: ctx.Err()}
			return
		}
	}
}

func (t *CollectorTransferPool) Results() <-chan CollectorResult {
	return t.results
}

func (t *CollectorTransferPool) TransferJob(zone string,
	v TConfigZone, mode int, soa dns.RR) {
	id := "(collector) (job)"

	if t.zones == nil {
		t.p.G().L.Debugf("%s skip job zone:'%s' as state is not read yet", id, zone)
		return
	}

	var job CollectorJob
	job.ClassJob = ClassJobTransfer
	job.Zone = zone
	job.ID = time.Now().UnixNano()
	job.Config = v
	job.Zones = t.zones

	var options TransferOptions
	options.Mode = mode
	options.Key = DefaultEmptyTSIG

	switch mode {
	case TransferModeIXFR:
		options.Serial = soa.(*dns.SOA).Serial
		options.Ns = soa.(*dns.SOA).Ns
		options.Mbox = soa.(*dns.SOA).Mbox
	}
	job.Options = &options

	t.jobs <- job
}

func (t *TReceiverPlugin) TransferPoolRun(ctx context.Context) error {
	var err error
	id := "(receiver) (pool)"

	workers := DefaultTransferPoolWorkers
	transfer := t.L().AxfrTransfer.Transfer
	if transfer.TransfersIn > 0 {
		workers = transfer.TransfersIn
	}
	t.G().L.Debugf("%s starting, workers count:'%d'", id, workers)

	var options CollectorTransferOptions
	options.Count = workers
	options.Dryrun = false

	// T.B.D. dryrun should be set somehow

	t.pool = NewCollectorTransferPool(t, &options)
	go t.pool.Run(ctx)

	for {
		// selecting results from transfer pool workers
		select {
		case r, ok := <-t.pool.Results():
			if !ok {
				t.G().L.Debugf("%s error on worker results", id)
				continue
			}
			if r.Error != nil {
				t.G().L.Errorf("%s job id:'%d' failed, err:'%s'",
					id, r.Job.ID, r.Error)
				continue
			}

			t.G().L.Debugf("%s result on worker:'%d' job id:'%d' processed OK, time:'%d'",
				id, r.ID, r.Job.ID, r.Processed)

		case <-ctx.Done():
			t.G().L.Debugf("%s context stop on thread pool", id)

			// starting also stop process for recevier notify
			// worker: it waits for shutdown
			t.Stop()
			//j.notifier = nil

			return ctx.Err()

		case <-t.pool.done:
			return err
		}
	}
}
